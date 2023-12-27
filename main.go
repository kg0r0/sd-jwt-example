package main

import (
	"log"

	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/TBD54566975/ssi-sdk/crypto/jwx"
	"github.com/TBD54566975/ssi-sdk/did/key"
	sdjwt "github.com/TBD54566975/ssi-sdk/sd-jwt"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

type lestratSigner struct {
	signer jwx.Signer
}

func (s lestratSigner) Sign(blindedClaimsData []byte) ([]byte, error) {
	insecureSDJWT, err := jwt.ParseInsecure(blindedClaimsData)
	if err != nil {
		return nil, err
	}

	signed, err := jwt.Sign(insecureSDJWT, jwt.WithKey(jwa.KeyAlgorithmFrom(s.signer.ALG), s.signer.PrivateKey))
	if err != nil {
		return nil, err
	}
	return signed, nil
}

func main() {
	issuerPrivKey, issuerDID, _ := key.GenerateDIDKey(crypto.P256)
	expandedIssuerDID, _ := issuerDID.Expand()
	issuerKID := expandedIssuerDID.VerificationMethod[0].ID

	credentialClaims := []byte(`{
	  "first_name": "Alice",
	  "address": "123 McAlice St, NY",
	  "date_of_birth": "1967-01-24"
	}`)

	issuerSigner, _ := jwx.NewJWXSigner(issuerDID.String(), issuerKID, issuerPrivKey)
	signer := sdjwt.NewSDJWTSigner(&lestratSigner{
		*issuerSigner,
	}, sdjwt.NewSaltGenerator(16))

	issuanceFormat, err := signer.BlindAndSign(credentialClaims, map[string]sdjwt.BlindOption{
		"first_name":    sdjwt.RecursiveBlindOption{},
		"address":       sdjwt.RecursiveBlindOption{},
		"date_of_birth": sdjwt.RecursiveBlindOption{},
	})
	if err != nil {
		log.Fatal(err)
		return
	}
	log.Println(string(issuanceFormat))

	idxOfDisclosuresToPresent, _ := sdjwt.SelectDisclosures(issuanceFormat, map[string]struct{}{"date_of_birth": {}})
	sdPresentation := sdjwt.CreatePresentation(issuanceFormat, idxOfDisclosuresToPresent, nil)
	log.Println(string(sdPresentation))

	issuerKey, _ := expandedIssuerDID.VerificationMethod[0].PublicKeyJWK.ToPublicKey()
	processedPayload, err := sdjwt.VerifySDPresentation(sdPresentation,
		sdjwt.VerificationOptions{
			HolderBindingOption: sdjwt.SkipVerifyHolderBinding,
			Alg:                 expandedIssuerDID.VerificationMethod[0].PublicKeyJWK.ALG,
			IssuerKey:           issuerKey,
		})
	if err != nil {
		log.Fatal(err)
		return
	}
	log.Println(processedPayload)
}
