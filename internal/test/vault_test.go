package vault

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"testing"

	"github.com/google/uuid"
	log "github.com/hashicorp/go-hclog"
	kv "github.com/hashicorp/vault-plugin-secrets-kv"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/audit"
	"github.com/hashicorp/vault/builtin/logical/pki"
	"github.com/hashicorp/vault/builtin/logical/ssh"
	"github.com/hashicorp/vault/builtin/logical/transit"
	"github.com/hashicorp/vault/helper/benchhelpers"
	"github.com/hashicorp/vault/helper/builtinplugins"
	"github.com/hashicorp/vault/sdk/helper/logging"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/hashicorp/vault/vault"

	auditFile "github.com/hashicorp/vault/builtin/audit/file"
	approle "github.com/hashicorp/vault/builtin/credential/approle"
	vaulthttp "github.com/hashicorp/vault/http"
)

var (
	defaultVaultCredentialBackends = map[string]logical.Factory{
		"approle": approle.Factory,
	}

	defaultVaultAuditBackends = map[string]audit.Factory{
		"file": auditFile.Factory,
	}

	defaultVaultLogicalBackends = map[string]logical.Factory{
		"generic-leased": vault.LeasedPassthroughBackendFactory,
		"pki":            pki.Factory,
		"ssh":            ssh.Factory,
		"transit":        transit.Factory,
		"kv":             kv.Factory,
	}
)

func testVaultServerUnseal(tb testing.TB) (*api.Client, []string, *vault.TestCluster) {
	tb.Helper()
	logger := log.NewInterceptLogger(&log.LoggerOptions{
		Output:     log.DefaultOutput,
		Level:      log.Error,
		JSONFormat: logging.ParseEnvLogFormat() == logging.JSONFormat,
	})

	coreConfig := vault.CoreConfig{
		DisableMlock:       true,
		DisableCache:       true,
		Logger:             logger,
		CredentialBackends: defaultVaultCredentialBackends,
		AuditBackends:      defaultVaultAuditBackends,
		LogicalBackends:    defaultVaultLogicalBackends,
		BuiltinRegistry:    builtinplugins.Registry,
		Seal:               nil,
	}
	opts := vault.TestClusterOptions{
		HandlerFunc: vaulthttp.Handler,
		NumCores:    1,
		KVVersion:   "1",
	}
	cluster := vault.NewTestCluster(benchhelpers.TBtoT(tb), &coreConfig, &opts)
	cluster.Start()

	// Make it easy to get access to the active
	core := cluster.Cores[0].Core
	vault.TestWaitActive(benchhelpers.TBtoT(tb), core)

	// Get the client already setup for us!
	client := cluster.Cores[0].Client
	client.SetToken(cluster.RootToken)
	var keys [][]byte
	if coreConfig.Seal != nil && coreConfig.Seal.RecoveryKeySupported() {
		keys = cluster.RecoveryKeys
	} else {
		keys = cluster.BarrierKeys
	}
	keysStr := make([]string, len(keys))
	for i := range keys {
		keysStr[i] = base64.StdEncoding.EncodeToString(keys[i])
	}
	return client, keysStr, cluster
}
func testVaultServer(tb testing.TB) (*api.Client, *vault.TestCluster) {
	tb.Helper()

	client, _, cluster := testVaultServerUnseal(tb)
	return client, cluster
}

func createVaultWithTestAppRole(t *testing.T, roleName string, path string) (*api.Client, *vault.TestCluster, string, string) {
	t.Helper()
	client, cluster := testVaultServer(t)

	policyName := "secrets-readonly"
	// setup a readonly policy
	{
		policy := "path \"secret/*\" { capabilities = [\"read\"] }"
		err := client.Sys().PutPolicy(policyName, policy)
		if err != nil {
			t.Fatal(err)
		}
	}

	if err := client.Sys().EnableAuthWithOptions("approle", &api.EnableAuthOptions{
		Type: "approle",
	}); err != nil {
		t.Fatal(err)
	}
	roleId := uuid.New().String()
	strmap := map[string]interface{}{
		"role_id":  roleId,
		"policies": policyName,
	}

	if _, err := client.Logical().Write("auth/"+path+"/role/"+roleName, strmap); err != nil {
		t.Fatal(err)
	}
	response, err := client.Logical().Write("auth/"+path+"/role/"+roleName+"/secret-id", strmap)
	if err != nil {
		t.Fatal(err)
	}

	// Access the secretId of "key"
	secretId, ok := response.Data["secret_id"].(string)
	if !ok {
		t.Fatal(err)
	}

	// for v := 0; v < 1; v += 0 {
	// 	fmt.Print(v)
	// 	time.Sleep(time.Second)
	// }

	return client, cluster, roleId, secretId
}

func insertSecretData(t *testing.T, secretInfo map[string]interface{}, client_with_rootToken *api.Client, mountPath string, secretPath string) {
	t.Helper()

	// setup some data for retrieval
	{
		wrappedData := map[string]interface{}{
			"data":            secretInfo,
			"custom_metadata": make(map[string]string),
		}
		// _, err := client_with_rootToken.KVv2(mountPath).Put(context.Background(), secretPath, wrappedData)
		_, err := client_with_rootToken.Logical().WriteWithContext(context.Background(), mountPath+"/data/"+secretPath, wrappedData)
		if err != nil {
			t.Fatal(err)
		}

	}
}

func TestGetSecretData(t *testing.T) {
	roleName := "pctl"
	path := "approle"
	client_with_rootToken, cluster, _, _ := createVaultWithTestAppRole(t, roleName, path)
	defer cluster.Cleanup()

	fmt.Printf("export VAULT_TOKEN=%s\nexport VAULT_ADDR=%s\nexport VAULT_CACERT=%s\n",
		client_with_rootToken.Token(),
		client_with_rootToken.Address(),
		cluster.CACertPEMFile)

	// fmt.Println(client_with_rootToken.Sys().ListMounts())

	_, err := os.ReadFile(cluster.CACertPEMFile)
	if err != nil {
		t.Fatalf("Error reading file: %s", err)
	}
	// prepare the secrets in the vault

	mountPath := "secret"
	secretPath := "randomsecret"
	secretData := uuid.New().String()
	secretField := "mypassword"
	{
		secretInfo := map[string]interface{}{
			secretField: secretData,
		}
		insertSecretData(t, secretInfo, client_with_rootToken, mountPath, secretPath)
	}

}
