package service_account

import (
	"fmt"
	"github.com/gin-gonic/gin"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	"nocalhost/internal/nocalhost-api/global"
	"nocalhost/internal/nocalhost-api/service"
	"nocalhost/pkg/nocalhost-api/app/api"
	"nocalhost/pkg/nocalhost-api/app/router/ginbase"
	"nocalhost/pkg/nocalhost-api/pkg/clientgo"
	"nocalhost/pkg/nocalhost-api/pkg/errno"
	"nocalhost/pkg/nocalhost-api/pkg/log"
	"nocalhost/pkg/nocalhost-api/pkg/setupcluster"
	"sync"
)

var (
	NOCALHOST_SA_KEY = "nocalhost.sa"
)

type SaAuthorizeRequest struct {
	ClusterId *uint64 `json:"cluster_id" binding:"required"`
	UserId    *uint64 `json:"user_id" binding:"required"`
	SpaceName string  `json:"space_name" binding:"required"`
}

func Authorize(c *gin.Context) {
	var req SaAuthorizeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		log.Warnf("bind service account authorizeRequest params err: %v", err)
		api.SendResponse(c, errno.ErrBind, nil)
		return
	}

	AuthorizeNsToUser(c, *req.ClusterId, *req.UserId, req.SpaceName)
}

func ListAuthorization(c *gin.Context) {
	userId, err := ginbase.LoginUser(c)
	if err != nil {
		api.SendResponse(c, errno.ErrLoginRequired, nil)
		return
	}

	// optimization required
	clusters, err := service.Svc.ClusterSvc().GetList(c)
	if err != nil {
		api.SendResponse(c, errno.ErrClusterNotFound, nil)
		return
	}

	user, err := service.Svc.UserSvc().GetUserByID(c, userId)
	if err != nil {
		api.SendResponse(c, errno.ErrUserNotFound, nil)
		return
	}

	var result []*ServiceAccountModel
	var lock sync.Mutex
	wg := sync.WaitGroup{}
	wg.Add(len(clusters))

	for _, cluster := range clusters {
		cluster := cluster
		go func() {

			defer wg.Done()
			// new client go
			clientGo, err := clientgo.NewAdminGoClient([]byte(cluster.KubeConfig))
			if err != nil {
				return
			}

			secret, err := clientGo.GetSecret(user.SaName, "default")
			if err != nil {
				return
			}

			kubeConfig, _, _ := setupcluster.NewDevKubeConfigReader(secret, cluster.Server, "default").GetCA().GetToken().AssembleDevKubeConfig().ToYamlString()

			crb, err := clientGo.GetClusterRoleBindingByLabel(fmt.Sprintf("%s=%s", NOCALHOST_SA_KEY, user.SaName))
			if err != nil {
				return
			}

			var nss []string
			for _, item := range crb.Items {
				nss = append(nss, item.Namespace)
			}

			lock.Lock()
			result = append(result, &ServiceAccountModel{
				KubeConfig:   kubeConfig,
				StorageClass: cluster.StorageClass,
				Namespaces:   nss,
			})
			lock.Unlock()
		}()
	}

	wg.Wait()
	api.SendResponse(c, nil, result)
}

func AuthorizeNsToUser(c *gin.Context, clusterId, userId uint64, ns string) {
	cluster, err := service.Svc.ClusterSvc().Get(c, clusterId)
	if err != nil {
		api.SendResponse(c, errno.ErrClusterNotFound, nil)
		return
	}

	// new client go
	clientGo, err := clientgo.NewAdminGoClient([]byte(cluster.KubeConfig))

	// get client go and check if is admin Kubeconfig
	if err != nil {
		switch err.(type) {
		case *errno.Errno:
			api.SendResponse(c, err, nil)
		default:
			api.SendResponse(c, errno.ErrClusterKubeErr, nil)
		}
		return
	}

	user, err := service.Svc.UserSvc().GetUserByID(c, userId)
	if err != nil {
		api.SendResponse(c, errno.ErrUserNotFound, nil)
		return
	}

	saName := user.SaName

	if err := createServiceAccountINE(clientGo, saName); err != nil {
		api.SendResponse(c, errno.ErrServiceAccountCreate, nil)
		return
	}

	if err := createNamespaceINE(clientGo, saName); err != nil {
		api.SendResponse(c, errno.ErrNameSpaceCreate, nil)
		return
	}

	if err := createClusterAdminRoleINE(clientGo); err != nil {
		api.SendResponse(c, errno.ErrClusterRoleCreate, nil)
		return
	}

	if err := createClusterRoleBindingINE(clientGo, ns, saName); err != nil {
		api.SendResponse(c, errno.ErrClusterRoleBindingCreate, nil)
		return
	}
}

func createServiceAccountINE(client *clientgo.GoClient, saName string) error {
	if _, err := client.CreateServiceAccount(saName, "default"); err != nil && !k8serrors.IsAlreadyExists(err) {
		return err
	}
	return nil
}

func createNamespaceINE(client *clientgo.GoClient, ns string) error {
	if _, err := client.CreateNS(ns, ""); err != nil && !k8serrors.IsAlreadyExists(err) {
		return err
	}
	return nil
}

func createClusterAdminRoleINE(client *clientgo.GoClient) error {
	if _, err := client.CreateClusterRole(global.NocalhostDevRoleName); err != nil && !k8serrors.IsAlreadyExists(err) {
		return err
	}
	return nil
}

func createClusterRoleBindingINE(client *clientgo.GoClient, ns, saName string) error {
	m := map[string]string{}
	m[NOCALHOST_SA_KEY] = saName

	if _, err := client.CreateClusterRoleBinding(fmt.Sprintf("%s-%s", saName, ns), ns, global.NocalhostDevRoleName, saName, m); err != nil && !k8serrors.IsAlreadyExists(err) {
		return err
	}
	return nil
}

type ServiceAccountModel struct {
	KubeConfig   string `gorm:"column:kubeconfig;not null" json:"kubeconfig"`
	StorageClass string `json:"storage_class" gorm:"column:storage_class"`
	Namespaces   []string
}
