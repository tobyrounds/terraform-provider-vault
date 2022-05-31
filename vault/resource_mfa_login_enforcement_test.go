package vault

import (
	"fmt"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"github.com/hashicorp/vault/api"

	"github.com/hashicorp/terraform-provider-vault/testutil"
)

func TestMFALoginEnforcementBasic(t *testing.T) {
	mfaLoginEnforcementName := acctest.RandomWithPrefix("login-enforce")
	identityEntityName := acctest.RandomWithPrefix("entity")
	identityGroupName := acctest.RandomWithPrefix("group")

	resource.Test(t, resource.TestCase{
		PreCheck:  func() { testutil.TestAccPreCheck(t) },
		Providers: testProviders,
		Steps: []resource.TestStep{
			{
				Config: testMFALoginEnforcementAccessorConfig(mfaLoginEnforcementName, identityEntityName, identityGroupName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("vault_mfa_login_enforcement.test", "name", mfaLoginEnforcementName),
					testLoginEnforcementAttr(mfaLoginEnforcementName, "mfa_method_ids", "vault_mfa_duo.test"),
					testLoginEnforcementAttr(mfaLoginEnforcementName, "auth_method_accessors", "vault_auth_backend.test-backend"),
					resource.TestCheckResourceAttr("vault_mfa_login_enforcement.test", "auth_method_types.#", "1"),
					resource.TestCheckResourceAttr("vault_mfa_login_enforcement.test", "auth_method_types.0", "userpass"),
					testLoginEnforcementAttr(mfaLoginEnforcementName, "identity_entity_ids", "vault_identity_entity.test"),
					testLoginEnforcementAttr(mfaLoginEnforcementName, "identity_group_ids", "vault_identity_group.test"),
				),
			},
		},
	})
}

func testMFALoginEnforcementAccessorConfig(name, identityName, groupName string) string {

	return fmt.Sprintf(`
	resource "vault_mfa_duo" "test" {
		secret_key            = "8C7THtrIigh2rPZQMbguugt8IUftWhMRCOBzbuyz"
		integration_key       = "BIACEUEAXI20BNWTEYXT"
		api_hostname          = "api-2b5c39f5.duosecurity.com"
	}
	
	resource "vault_auth_backend" "test-backend" {
		type = "userpass"
	}

	resource "vault_identity_entity" "test" {
		name = %q
	}

	resource "vault_identity_group" "test" {
		name = %q
	}

	resource "vault_mfa_login_enforcement" "test" {
		name            	  = %q
		mfa_method_ids 		  = [vault_mfa_duo.test.id]
		auth_method_accessors = [vault_auth_backend.test-backend.accessor]
		auth_method_types	  = ["userpass"]
		identity_entity_ids	  = [vault_identity_entity.test.id]
		identity_group_ids	  = [vault_identity_group.test.id]
	}
	`, identityName, groupName, name)
}

func testLoginEnforcementAttr(mfaLoginEnforcementName, attribute, dummyTarget string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		resourceState := s.Modules[0].Resources[dummyTarget]

		if resourceState == nil {
			return fmt.Errorf("resource not found in state")
		}

		instanceState := resourceState.Primary
		if instanceState == nil {
			return fmt.Errorf("resource has no primary instance")
		}

		var dummyTargetId string
		if attribute == "auth_method_accessors" {
			dummyTargetId = instanceState.Attributes["accessor"]
		} else {
			dummyTargetId = instanceState.Attributes["id"]
		}

		resourceState = s.Modules[0].Resources["vault_mfa_login_enforcement.test"]

		if resourceState == nil {
			return fmt.Errorf("resource not found in state")
		}

		instanceState = resourceState.Primary
		if instanceState == nil {
			return fmt.Errorf("resource has no primary instance")
		}

		client := testProvider.Meta().(*api.Client)
		resp, err := client.Logical().Read("identity/mfa/login-enforcement/" + strings.Trim(instanceState.ID, "/"))
		if err != nil {
			return err
		}

		clientAttrIds := resp.Data[attribute].([]interface{})
		if len(clientAttrIds) > 1 {
			return fmt.Errorf("Login Enforcement attribute '%s' has too many elements, only 1 configured", attribute)
		}
		if dummyTargetId != clientAttrIds[0] {
			return fmt.Errorf("State attribute element %q does not equal Login Enforcement attribute element %q", dummyTargetId, clientAttrIds[0].(string))
		}

		return nil
	}
}
