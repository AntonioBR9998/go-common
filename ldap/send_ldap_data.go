package ldap

import (
	"context"
	"errors"

	commonErr "github.com/AntonioBR9998/go-common/errors"
	"github.com/go-ldap/ldap/v3"
	log "github.com/sirupsen/logrus"
)

type SendData interface {
	AddRequest(ctx context.Context, entries []*ldap.Entry) error
	ModifyRequest(ctx context.Context, entries []*ldap.Entry) error
	DeleteRequest(ctx context.Context, dns []string) error
	DeleteByObjectGUID(ctx context.Context, objectGUID string) error
}

// AddRequest adds one or more LDAP entries to the directory server.
// Returns an error if the LDAP connection check fails or if any Add operation fails
// TODO: Rollback if something fails
func (c *ldapClient) AddRequest(ctx context.Context, entries []*ldap.Entry) error {
	for _, entry := range entries {
		log.Trace("Adding ldap.Entry, DN: ", entry.DN)

		// Transform ldap.EntryAttribute in ldap.Attribute
		attributes := []ldap.Attribute{}
		for _, entryAttr := range entry.Attributes {
			ldapAttr := ldap.Attribute{
				Type: entryAttr.Name,
				Vals: entryAttr.Values,
			}

			attributes = append(attributes, ldapAttr)
			log.Tracef("Attribute with name %s has been proccessed", ldapAttr.Type)
		}

		log.Debug("Building AddRequest struct")
		addRequest := ldap.AddRequest{
			DN:         entry.DN,
			Attributes: attributes,
			Controls:   nil,
		}

		// Checking LDAP connection
		err := c.checkLDAPConnection(ctx)
		if err != nil {
			log.Errorf("Error adding request with DN %s. Error: %v ", addRequest.DN, err)
			return err
		}

		// Add request
		log.Debug("Trying add request. URL: ", c.Cfg.Url)
		if err := c.conn.Add(&addRequest); err != nil {
			log.Errorf("Error adding request with DN %s. Error: %v ", addRequest.DN, err)
			return err
		}

		log.Infof("DN %s has been added successfully", addRequest.DN)
	}

	return nil
}

// ModifyRequest modifies LDAP entries
// TODO: Rollback if something fails
func (c *ldapClient) ModifyRequest(ctx context.Context, entries []*ldap.Entry) error {
	for _, entry := range entries {
		log.Trace("Modifying ldap.Entry, DN: ", entry.DN)
		modifyRequest := ldap.NewModifyRequest(entry.DN, nil)

		for _, entryAttr := range entry.Attributes {
			log.Tracef("Replacing attribute %s", entryAttr.Name)
			modifyRequest.Replace(entryAttr.Name, entryAttr.Values)
		}

		// Checking LDAP connection
		err := c.checkLDAPConnection(ctx)
		if err != nil {
			log.Errorf("Error modifying DN %s. Error: %v", entry.DN, err)
			return err
		}

		// Modify request
		log.Debug("Trying modify request. URL: ", c.Cfg.Url)
		if err := c.conn.Modify(modifyRequest); err != nil {
			log.Errorf("Error modifying DN %s. Error: %v", entry.DN, err)
			return err
		}

		log.Infof("DN %s has been modified successfully", entry.DN)
	}

	return nil
}

// DeleteRequest deletes LDAP entries by their DNs
// TODO: Rollback if something fails
func (c *ldapClient) DeleteRequest(ctx context.Context, dns []string) error {
	for _, dn := range dns {
		log.Debug("Deleting DN: ", dn)
		deleteRequest := ldap.NewDelRequest(dn, nil)

		// Checking LDAP connection
		err := c.checkLDAPConnection(ctx)
		if err != nil {
			log.Errorf("Error deleting DN %s. Error: %v", dn, err)
			return err
		}

		// Delete request
		log.Debug("Trying delete request. URL: ", c.Cfg.Url)
		if err := c.conn.Del(deleteRequest); err != nil {
			log.Errorf("Error deleting DN %s. Error: %v", dn, err)
			return err
		}

		log.Infof("DN %s has been deleted successfully", dn)
	}

	return nil
}

// DeleteByObjectGUID deletes an LDAP entry by its objectGUID.
// It searches for the entry using the provided objectGUID, retrieves its DN,
// and then deletes the entry from the LDAP directory.
// Returns nil if the entry is successfully deleted or if no entry is found.
// Returns an error if the LDAP connection check fails, the search fails, or the delete operation fails
func (c *ldapClient) DeleteByObjectGUID(ctx context.Context, objectGUID string) error {
	log.Debug("Deleting entry with objectGUID: ", objectGUID)

	// Getting DN from objectGUID
	dn, err := c.GetDNByObjectGUID(ctx, objectGUID)
	if err != nil {
		var notFoundErr *commonErr.NotFoundError
		if errors.As(err, &notFoundErr) {
			log.Warnf("No entry found for objectGUID '%s'. Nothing to delete", objectGUID)
			return nil // Ignore error if no entry found
		}
		log.Errorf("Error getting DN for objectGUID %s. Error: %v", objectGUID, err)
		return err
	}

	// Building delete request
	deleteRequest := ldap.NewDelRequest(*dn, nil)

	// Delete request
	log.Debug("Trying delete request. URL: ", c.Cfg.Url)
	if err := c.conn.Del(deleteRequest); err != nil {
		log.Errorf("Error deleting DN '%s' for objectGUID '%s'. Error: %v", *dn, objectGUID, err)
		return err
	}

	log.Infof("Entry with objectGUID '%s' and DN '%s' has been deleted successfully", objectGUID, *dn)

	return nil
}
