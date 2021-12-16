package gothsaml

import (
	"encoding/base64"
	"encoding/json"
	"errors"

	"github.com/crewjam/saml"
	"github.com/markbates/goth"
)

// Session is a CAS authentication session.
type Session struct {
	SPEntityID string
	SAMLAssertion *saml.Assertion
}

// GetAuthURL constructs a SAML request as an HTTP redirect and returns it.
func (s *Session) GetAuthURL() (string, error) {
	sp, ok := serviceProviders[s.SPEntityID]
	if !ok {
		return "", errors.New("Service provider for goth session not found")
	}
	authUrl, err := sp.MakeRedirectAuthenticationRequest("")
	if err != nil {
		return "", err
	}
	return authUrl.String(), nil
}

// Marshal returns a string representation of the session.
func (s *Session) Marshal() string {
	marshaled, _ := json.Marshal(s)
	return string(marshaled)
}

// Authorize validates the CAS ticket against the server, stores it, and
// returns the ticket.
func (s *Session) Authorize(provider goth.Provider, params goth.Params) (string, error) {
	sp, ok := serviceProviders[s.SPEntityID]
	if !ok {
		return "", errors.New("Service provider for goth session not found")
	}

	decodedResponse, err := base64.StdEncoding.DecodeString(params.Get("SAMLResponse"))
	if err != nil {
		return "", err
	}

	s.SAMLAssertion, err = sp.ParseXMLResponse(decodedResponse, nil)
	if err != nil {
		return "", err
	}

	return "", nil
}
