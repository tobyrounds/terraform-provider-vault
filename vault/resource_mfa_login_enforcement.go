package vault

import (
	"fmt"
	"log"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/vault/api"
)

func mfaLoginEnforcementResource() *schema.Resource {
	return &schema.Resource{
		Create: mfaLoginEnforcementWrite,
		Update: mfaLoginEnforcementWrite,
		Delete: mfaLoginEnforcementDelete,
		Read:   mfaLoginEnforcementRead,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},

		Schema: map[string]*schema.Schema{
			"name": {
				Type:         schema.TypeString,
				Required:     true,
				Description:  "Name for this login enforcement configuration.",
				ValidateFunc: validateNoTrailingSlash,
			},
			"mfa_method_ids": {
				Type:     schema.TypeSet,
				Required: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Description: "Array of MFA method UUIDs to use. These will be ORed together, meaning if several IDs are specified, any one of them is sufficient to login.",
			},
			"auth_method_accessors": {
				Type:     schema.TypeSet,
				Optional: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Description: "Array of auth mount accessor IDs. If present, only auth methods corresponding to the given accessors are checked during login.",
			},
			"auth_method_types": {
				Type:     schema.TypeSet,
				Optional: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Description: "Array of auth method types. If present, only auth methods corresponding to the given types are checked during login.",
			},
			"identity_group_ids": {
				Type:     schema.TypeSet,
				Optional: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Description: "Array of identity group IDs. If present, only entities belonging to one of the given groups are checked during login. Note that these IDs can be from the current namespace or a child namespace.",
			},
			"identity_entity_ids": {
				Type:     schema.TypeSet,
				Optional: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Description: "Array of identity entity IDs. If present, only entities with the given IDs are checked during login. Note that these IDs can be from the current namespace or a child namespace.",
			},
		},
	}
}

func mfaLoginEnforcementWrite(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)
	name := d.Get("name").(string)

	authMethodAccessors := d.Get("auth_method_accessors").(*schema.Set).List()
	authMethodTypes := d.Get("auth_method_types").(*schema.Set).List()
	identityGroupIds := d.Get("identity_group_ids").(*schema.Set).List()
	identityEntityIds := d.Get("identity_entity_ids").(*schema.Set).List()

	if len(authMethodAccessors) == 0 && len(authMethodTypes) == 0 && len(identityGroupIds) == 0 && len(identityEntityIds) == 0 {
		return fmt.Errorf("One of auth_method_accessors, auth_method_types, identity_group_ids, identity_entity_ids must be set.")
	}

	data := map[string]interface{}{}
	mfaLoginEnforcementUpdateFields(d, data)

	log.Printf("[DEBUG] Updating mfaLoginEnforcement method %s in Vault", name)
	_, err := client.Logical().Write(mfaLoginEnforcementPath(name), data)

	if err != nil {
		return fmt.Errorf("error writing to Vault: %s", err)
	}
	log.Printf("[DEBUG] Wrote mfaLoginEnforcement '%s' in Vault", name)

	return mfaLoginEnforcementRead(d, meta)
}

func mfaLoginEnforcementDelete(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	name := d.Get("name").(string)

	log.Printf("[DEBUG] Deleting mfaLoginEnforcement '%s' from Vault", mfaLoginEnforcementPath(name))

	_, err := client.Logical().Delete(mfaLoginEnforcementPath(name))

	if err != nil {
		return fmt.Errorf("error deleting from Vault: %s", err)
	}

	return nil
}

func mfaLoginEnforcementRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*api.Client)

	name := d.Get("name").(string)

	resp, err := client.Logical().Read(mfaLoginEnforcementPath(name))

	if err != nil {
		return fmt.Errorf("error reading from Vault: %s", err)
	}

	log.Printf("[DEBUG] Read MFA login enforcement '%q'", mfaLoginEnforcementPath(name))

	d.Set("name", resp.Data["name"])
	d.Set("mfa_method_ids", resp.Data["mfa_method_ids"])
	d.Set("auth_method_accessors", resp.Data["auth_method_accessors"])
	d.Set("auth_method_types", resp.Data["auth_method_types"])
	d.Set("identity_group_ids", resp.Data["identity_group_ids"])
	d.Set("identity_entity_ids", resp.Data["identity_entity_ids"])

	d.SetId(name)

	return nil
}

func mfaLoginEnforcementUpdateFields(d *schema.ResourceData, data map[string]interface{}) {

	if v, ok := d.GetOk("name"); ok {
		data["name"] = v.(string)
	}

	if v, ok := d.GetOk("mfa_method_ids"); ok {
		data["mfa_method_ids"] = v.(*schema.Set).List()
	}

	if v, ok := d.GetOk("auth_method_accessors"); ok {
		data["auth_method_accessors"] = v.(*schema.Set).List()
	}

	if v, ok := d.GetOk("auth_method_types"); ok {
		data["auth_method_types"] = v.(*schema.Set).List()
	}

	if v, ok := d.GetOk("identity_group_ids"); ok {
		data["identity_group_ids"] = v.(*schema.Set).List()
	}

	if v, ok := d.GetOk("identity_entity_ids"); ok {
		data["identity_entity_ids"] = v.(*schema.Set).List()
	}

}

func mfaLoginEnforcementPath(name string) string {
	return "identity/mfa/login-enforcement/" + strings.Trim(name, "/")
}
