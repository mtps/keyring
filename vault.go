package keyring

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/hashicorp/vault/api"
	"os"
	path2 "path"
	"strings"
)

type vaultKeyring struct {
	vault *api.Client

	prefix string
	address string
	token string
}

type vaultData struct {
	Item []byte `json:"item"`
}

type vaultEntry struct {
	Data vaultData `json:"data"`
}

var _ Keyring = (*vaultKeyring)(nil)

func init() {
	supportedBackends[VaultBackend] = opener(func(cfg Config) (Keyring, error) {
		if cfg.ServiceName == "" {
			cfg.ServiceName = "vault"
		}

		if cfg.VaultPrefix == "" {
			cfg.VaultPrefix = "secret/keyring"
		}

		if cfg.VaultAddress == "" {
			cfg.VaultAddress = "localhost:8200"
		}

		if cfg.VaultToken == "" {
			cfg.VaultToken = os.Getenv("VAULT_TOKEN")
		}

		vaultConfig := api.DefaultConfig()
		vaultConfig.Address = cfg.VaultAddress

		client, err := api.NewClient(vaultConfig)
		if err != nil {
			return &vaultKeyring{}, err
		}

		if err := client.SetAddress(cfg.VaultAddress); err != nil {
			return &vaultKeyring{}, err
		}

		client.SetToken(cfg.VaultToken)

		ring := &vaultKeyring{
			vault: client,
			prefix: cfg.VaultPrefix,
			address: cfg.VaultAddress,
			token: cfg.VaultToken,
		}

		return ring, nil
	})
}

func (v vaultKeyring) Get(key string) (Item, error) {
	path, err := v.keyPath(key, "data")
	if err != nil {
		return Item{}, err
	}

	secret, err := v.vault.Logical().Read(path)
	if err != nil {
		return Item{}, err
	}

	if secret == nil {
		return Item{}, ErrKeyNotFound
	}

	item, err := v.unwrapItem(secret.Data)
	if err != nil {
		return Item{}, err
	}

	return item, nil
}

func (v vaultKeyring) GetMetadata(_ string) (Metadata, error) {
	return Metadata{}, ErrMetadataNeedsCredentials
}

func (v vaultKeyring) Set(item Item) error {
	bz, err := v.wrapItem(item)
	if err != nil {
		return err
	}

	path, err := v.keyPath(item.Key, "data")
	if err != nil {
		return err
	}

	_, err = v.vault.Logical().Write(path, bz)
	if err != nil {
		return err
	}

	return nil
}

func (v vaultKeyring) Remove(key string) error {
	path, err := v.keyPath(key, "data")
	if err != nil {
		return err
	}

	_, err = v.vault.Logical().Delete(path)
	if err != nil {
		return err
	}

	return nil
}

func (v vaultKeyring) Keys() ([]string, error) {
	path, err := v.keyPath("", "metadata")
	if err != nil {
		return []string{}, err
	}

	list, err := v.vault.Logical().List(path)
	if err != nil {
		return []string{}, err
	}

	if list == nil {
		return []string{}, nil
	}

	data, ok := list.Data["keys"].([]interface{})
	if !ok {
		return []string{}, fmt.Errorf("error retrieving key data")
	}

	var keys []string
	for _, key := range data {
		keys = append(keys, key.(string))
	}
	return keys, nil
}

func (v vaultKeyring) keyPath(key string, apiPrefix string) (string, error) {
	var path string
	if key == "" {
		path = v.prefix
	} else {
		path = fmt.Sprintf("%s/%s", v.prefix, key)
	}

	mountPath, v2, err := isKVv2(path, v.vault)
	if err != nil {
		return "", err
	}

	if v2 {
		path = addPrefixToVKVPath(path, mountPath, apiPrefix)
	}

	return path, nil
}

func (v vaultKeyring) wrapItem(item Item) (map[string]interface{}, error) {
	bz, err := json.Marshal(item)
	if err != nil {
		return nil, fmt.Errorf("error marshal vault item data")
	}

	return map[string]interface{}{"data": map[string]interface{}{"item": bz}}, nil
}

func (v vaultKeyring) unwrapItem(vaultItem map[string]interface{}) (Item, error) {
	data, ok := vaultItem["data"].(map[string]interface{})
	if !ok {
		return Item{}, fmt.Errorf("error parsing vault data")
	}

	bz, ok := data["item"].(string)
	if !ok {
		return Item{}, fmt.Errorf("error parsing vault item data")
	}

	unb64, err := base64.StdEncoding.DecodeString(bz)
	if err != nil {
		return Item{}, fmt.Errorf("error decoding vault item data")
	}

	item := Item{}
	if err := json.Unmarshal(unb64, &item); err != nil {
		return Item{}, fmt.Errorf("error unmarshal vault item data")
	}

	return item, nil
}

// Pulled from the vault commands.
func kvPreflightVersionRequest(client *api.Client, path string) (string, int, error) {
	// We don't want to use a wrapping call here so save any custom value and
	// restore after
	currentWrappingLookupFunc := client.CurrentWrappingLookupFunc()
	client.SetWrappingLookupFunc(nil)
	defer client.SetWrappingLookupFunc(currentWrappingLookupFunc)
	currentOutputCurlString := client.OutputCurlString()
	client.SetOutputCurlString(false)
	defer client.SetOutputCurlString(currentOutputCurlString)

	r := client.NewRequest("GET", "/v1/sys/internal/ui/mounts/"+path)
	resp, err := client.RawRequest(r)
	if resp != nil {
		defer resp.Body.Close()
	}
	if err != nil {
		// If we get a 404 we are using an older version of vault, default to
		// version 1
		if resp != nil && resp.StatusCode == 404 {
			return "", 1, nil
		}

		return "", 0, err
	}

	secret, err := api.ParseSecret(resp.Body)
	if err != nil {
		return "", 0, err
	}
	if secret == nil {
		return "", 0, fmt.Errorf("nil response from pre-flight request")
	}
	var mountPath string
	if mountPathRaw, ok := secret.Data["path"]; ok {
		mountPath = mountPathRaw.(string)
	}
	options := secret.Data["options"]
	if options == nil {
		return mountPath, 1, nil
	}
	versionRaw := options.(map[string]interface{})["version"]
	if versionRaw == nil {
		return mountPath, 1, nil
	}
	version := versionRaw.(string)
	switch version {
	case "", "1":
		return mountPath, 1, nil
	case "2":
		return mountPath, 2, nil
	}

	return mountPath, 1, nil
}

func isKVv2(path string, client *api.Client) (string, bool, error) {
	mountPath, version, err := kvPreflightVersionRequest(client, path)
	if err != nil {
		return "", false, err
	}

	return mountPath, version == 2, nil
}

func addPrefixToVKVPath(p, mountPath, apiPrefix string) string {
	switch {
	case p == mountPath, p == strings.TrimSuffix(mountPath, "/"):
		return path2.Join(mountPath, apiPrefix)
	default:
		p = strings.TrimPrefix(p, mountPath)
		return path2.Join(mountPath, apiPrefix, p)
	}
}
