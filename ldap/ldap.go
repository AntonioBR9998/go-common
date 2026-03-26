package ldap

import (
	"context"
	"crypto/tls"
	"time"

	"github.com/go-ldap/ldap/v3"
	log "github.com/sirupsen/logrus"
)

type LdapClient interface {
	SendData
	RequestData
	Close() error
	BindRequest(ctx context.Context, bindDN string, bindPass string) error
}

type ldapClient struct {
	Cfg  LdapConfig
	conn *ldap.Conn
}

type LdapConfig struct {
	Url                   string
	BaseDN                string
	BindDN                string
	BindPass              string
	BackoffConfig         BackoffConfig
	TlsInsecureSkipVerify bool
	ReconnectTimeout      time.Duration
}

type BackoffConfig struct {
	MinDelay   time.Duration
	Multiplier int64
}

func NewLDAPClient(ctx context.Context, cfg LdapConfig) (LdapClient, error) {
	c := ldapClient{
		Cfg: cfg,
	}

	// Connecting to LDAP
	var err error
	c.conn, err = c.connectWithBackoff(ctx, c.Cfg)
	if err != nil {
		log.Error("Error starting new LDAP client: ", err)
		return nil, err
	}

	return &c, nil
}

func (c *ldapClient) Close() error {
	if c.conn == nil {
		log.Warnf("LDAP connection with %s is already closed", c.Cfg.Url)
		return nil
	}

	if err := c.conn.Close(); err != nil {
		log.Errorf("Error closing LDAP connection with %s. Error: %v", c.Cfg.Url, err)
		return err
	}

	log.Infof("LDAP connection with %s has been closed successfully", c.Cfg.Url)
	return nil
}

func (c *ldapClient) BindRequest(ctx context.Context, username string, bindPass string) error {
	log.Debugf("Binding with username: %s", username)

	// Checking LDAP connection
	err := c.checkLDAPConnection(ctx)
	if err != nil {
		log.Error("LDAP connection failed: ", err)
		return err
	}

	err = c.conn.Bind(username, bindPass)
	if err != nil {
		log.Errorf("Error binding with username %s. Error: %v", username, err)
		return err
	}

	log.Infof("Bind successful with username: %s", username)
	return nil
}

// This function try to connect with LDAP until a successfull connection
func (c *ldapClient) connectWithBackoff(ctx context.Context, cfg LdapConfig) (*ldap.Conn, error) {
	delay := cfg.BackoffConfig.MinDelay

	for attempt := 1; true; attempt++ {
		if err := ctx.Err(); err != nil {
			log.Warn("starting LDAP connection cancelled: ", err)
			return nil, err
		}

		log.Debugf("Trying to connect LDAP in %s with tls.Config InsecureSkipVerify=%v",
			cfg.Url,
			cfg.TlsInsecureSkipVerify,
		)

		conn, err := ldap.DialURL(
			cfg.Url,
			ldap.DialWithTLSConfig(&tls.Config{InsecureSkipVerify: cfg.TlsInsecureSkipVerify}),
		)
		if err == nil {
			log.Info("LDAP connection has been established with: ", cfg.Url)
			log.Debugf("Binding as %s", cfg.BindDN)

			err = conn.Bind(cfg.BindDN, cfg.BindPass)
			if err == nil {
				log.Info("Bind successful with username: ", cfg.BindDN)
				return conn, nil // Connection stablished
			}

			conn.Close()
		}
		log.Errorf("LDAP connection fail. Attemp: %d. Retrying in %f seconds. Error: %v", attempt, delay.Seconds(), err)
		time.Sleep(delay)

		// Exponential backoff
		delay = time.Duration(int64(delay) * cfg.BackoffConfig.Multiplier)
	}

	return nil, nil
}

// TODO: The go-ldap library is not designed for or supports concurrency.
// Therefore, in principle, race conditions should not occur.
// The solution for parallelising multiple LDAP requests would be to have a pool of connections from different LDAP clients.
// Also, it is not considered necessary at this time to have a mutex for the connection and a small state machine.
func (c *ldapClient) checkLDAPConnection(ctx context.Context) error {
	log.Debugf("Checking LDAP connection. Binding as %s", c.Cfg.BindDN)

	if c.conn == nil {
		log.Warn("LDAP connection is nil. Retrying")
		ctxTimeout, cancel := context.WithTimeout(ctx, c.Cfg.ReconnectTimeout)
		defer cancel()

		var err error
		log.Debugf("Waiting up to %f seconds to reconnect", c.Cfg.ReconnectTimeout.Seconds())
		c.conn, err = c.connectWithBackoff(ctxTimeout, c.Cfg)
		if err != nil {
			log.Error("Error checking LDAP connection while trying to reconnect: ", err)
			return err
		}
	}
	_, err := c.conn.WhoAmI(nil) // If proxy auth is not used, controls are not required (nil)
	if err != nil {
		log.Warn("LDAP connection lost. Retrying")
		c.Close()

		log.Debugf("Waiting up to %f seconds to reconnect", c.Cfg.ReconnectTimeout.Seconds())
		ctxTimeout, cancel := context.WithTimeout(ctx, c.Cfg.ReconnectTimeout)
		defer cancel()

		c.conn, err = c.connectWithBackoff(ctxTimeout, c.Cfg)
		if err != nil {
			log.Error("Error checking LDAP connection while trying to reconnect: ", err)
			return err
		}
	}

	log.Infof("LDAP connection with %s has been checked", c.Cfg.Url)
	return nil
}
