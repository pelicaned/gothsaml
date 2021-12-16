package gothsaml

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/xml"
	"errors"
	"net/url"

	"github.com/crewjam/saml"
	"github.com/markbates/goth"
	"golang.org/x/oauth2"
)

var serviceProviders = make(map[string]*saml.ServiceProvider)

// AttributeMap defines the relationship between SAML attributes and the goth
// user definition.
type AttributeMap struct {
	Email       string
	Name        string
	FirstName   string
	LastName    string
	NickName    string
	Description string
	UserID      string
	AvatarURL   string
	Location    string
}

// Provider is an implementation of `goth.Provider` to authenticate against a
// CAS URL.
type Provider struct {
	name         string
	sp           *saml.ServiceProvider
	attributeMap *AttributeMap
}

// New constructs a Provider with with the given parameters.
func New(cert *x509.Certificate, key *rsa.PrivateKey, idp *saml.EntityDescriptor, metadataUrl string, acsUrl string, sloUrl string, attributeMap *AttributeMap) (*Provider, []byte, error) {
	metadataUrlParsed, err := url.Parse(metadataUrl)
	if err != nil {
		return nil, nil, err
	}
	acsUrlParsed, err := url.Parse(acsUrl)
	if err != nil {
		return nil, nil, err
	}

	p := &Provider{
		name: "saml",
		sp: &saml.ServiceProvider{
			EntityID:          metadataUrl,
			Key:               key,
			Certificate:       cert,
			MetadataURL:       *metadataUrlParsed,
			AcsURL:            *acsUrlParsed,
			IDPMetadata:       idp,
			ForceAuthn:        nil,
			AllowIDPInitiated: true,
		},
		attributeMap: attributeMap,
	}

	// Marshal metadata for use by the web server.
	metadataXml, err := xml.Marshal(p.sp.Metadata())

	// We don't store the SP in the session itself (since it is encoded and
	// sent to the user, which would be a security issue), so we will track it
	// in an in-memory map.
	serviceProviders[p.sp.EntityID] = p.sp

	return p, metadataXml, nil
}

// Name returns the name of the provider.
func (p *Provider) Name() string {
	return p.name
}

// SetName sets the name of the provider.
func (p *Provider) SetName(name string) {
	p.name = name
}

// BeginAuth returns a session attached to the current SP's EntityID.
func (p *Provider) BeginAuth(state string) (goth.Session, error) {
	// We don't store the SP in the session itself.
	if _, ok := serviceProviders[p.sp.EntityID]; !ok {
		serviceProviders[p.sp.EntityID] = p.sp
	}

	s := &Session{
		SPEntityID: p.sp.EntityID,
	}

	return s, nil
}

// UnmarshalSession returns the session represented by the given string.
func (p *Provider) UnmarshalSession(data string) (goth.Session, error) {
	s := &Session{}
	err := json.Unmarshal([]byte(data), s)
	if err != nil {
		return nil, err
	}
	return s, nil
}

// FetchUser attaches the SAML assertions, if present, in the session to a goth
// user, under a single key in the RawData "saml".
func (p *Provider) FetchUser(sess goth.Session) (goth.User, error) {
	s := sess.(*Session)
	if s.SAMLAssertion == nil {
		return goth.User{}, errors.New("User information has not yet been fetched")
	}

	attributes := make(map[string]interface{})
	for _, attributeStatement := range s.SAMLAssertion.AttributeStatements {
		for _, attribute := range attributeStatement.Attributes {
			if _, ok := attributes[attribute.Name]; !ok {
				attributes[attribute.Name] = make([]string, 0)
			}
			for _, value := range attribute.Values {
				attributes[attribute.Name] = append(attributes[attribute.Name].([]string), value.Value)
			}
		}
	}
	getAttribute := func(name string) string {
		valuesIface, ok := attributes[name]
		if !ok {
			return ""
		}
		values := valuesIface.([]string)
		if len(values) == 0 {
			return ""
		}
		return values[0]
	}

	u := goth.User{
		RawData:     attributes,
		Provider:    p.Name(),
		Email:       getAttribute(p.attributeMap.Email),
		Name:        getAttribute(p.attributeMap.Name),
		FirstName:   getAttribute(p.attributeMap.FirstName),
		LastName:    getAttribute(p.attributeMap.LastName),
		NickName:    getAttribute(p.attributeMap.NickName),
		Description: getAttribute(p.attributeMap.Description),
		UserID:      getAttribute(p.attributeMap.UserID),
		AvatarURL:   getAttribute(p.attributeMap.AvatarURL),
		Location:    getAttribute(p.attributeMap.Location),
	}

	return u, nil
}

// Debug is a no-op.
func (p *Provider) Debug(debug bool) {}

// RefreshToken is not implemented.
func (p *Provider) RefreshToken(refreshToken string) (*oauth2.Token, error) {
	return nil, nil
}

// RefreshTokenAvailable returns false, because RefreshToken is not
// implemented.
func (p *Provider) RefreshTokenAvailable() bool {
	return false
}
