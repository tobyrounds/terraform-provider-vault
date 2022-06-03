package vault

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"

	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestDataSourceKVSecretList(t *testing.T) {
	mount := acctest.RandomWithPrefix("tf-kv")
	s1 := acctest.RandomWithPrefix("foo")
	s2 := acctest.RandomWithPrefix("bar")

	datasourceName := "data.vault_kv_secret_list.test"

	resource.Test(t, resource.TestCase{
		Providers: testProviders,
		PreCheck:  func() { testutil.TestAccPreCheck(t) },
		Steps: []resource.TestStep{
			{
				Config: testDataSourceKVSecretListConfig(mount, s1, s2),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(datasourceName, "path", fmt.Sprintf("%s", mount)),
					resource.TestCheckResourceAttr(datasourceName, "names.#", "3"),
					resource.TestCheckResourceAttr(datasourceName, "names.0", s2),
					resource.TestCheckResourceAttr(datasourceName, "names.1", fmt.Sprintf("%s/", s2)),
					resource.TestCheckResourceAttr(datasourceName, "names.2", s1),
				),
			},
		},
	})
}

func testDataSourceKVSecretListConfig(mount, secretPath1, secretPath2 string) string {
	return fmt.Sprintf(`
%s

resource "vault_kv_secret" "test_1" {
  path = "${vault_mount.kvv1.path}/%s"
  data_json = jsonencode(
    {
      zip = "zap",
      foo = "bar"
    }
  )
}

resource "vault_kv_secret" "test_2" {
  path = "${vault_mount.kvv1.path}/%s"
  data_json = jsonencode(
    {
      zip = "zap",
      foo = "bar"
    }
  )
}

resource "vault_kv_secret" "test_nested" {
  path = "${vault_kv_secret.test_2.path}/biz"
  data_json = jsonencode(
    {
      zip = "zap",
      foo = "bar"
    }
  )
}

data "vault_kv_secret_list" "test" {
  path       = vault_mount.kvv1.path
  depends_on = [vault_kv_secret.test_nested, vault_kv_secret.test_1]
}`, kvV1MountConfig(mount), secretPath1, secretPath2)
}
