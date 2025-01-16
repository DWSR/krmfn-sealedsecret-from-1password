package krmfnsealedsecretfrom1password

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"io"
	"log/slog"
	"strings"

	"github.com/DWSR/krmfn-sealedsecret-from-1password/internal/secretsstore"
	ssv1alpha1 "github.com/bitnami-labs/sealed-secrets/pkg/apis/sealedsecrets/v1alpha1"
	"github.com/bitnami-labs/sealed-secrets/pkg/crypto"
	"github.com/bitnami-labs/sealed-secrets/pkg/kubeseal"
	"sigs.k8s.io/kustomize/kyaml/fn/framework"
	"sigs.k8s.io/kustomize/kyaml/yaml"
)

type (
	// Processor processes SealedSecrets in a ResourceList by resolving references to 1Password secrets.
	Processor struct {
		//nolint:containedctx
		ctx     context.Context // yes you shouldn't do this
		client  secretsstore.SecretsStore
		randSrc io.Reader
	}

	// Config is the configuration for the function.
	Config struct {
		// Token is the 1Password service account token.
		Token string `flag:"required" json:"onePasswordServiceAccountToken" param:"onepassword-service-account-token,t"`
		// CertString is the certificate used to seal the secrets
		CertString string `flag:"required" json:"sealingCert" param:"sealing-cert,c"`
	}

	// ProcessorOption is a function that configures a Processor.
	ProcessorOption func(*Processor)
)

var (
	// ErrLoadConfig is returned when the function configuration cannot be loaded, such as not having the required fields.
	ErrLoadConfig = errors.New("unable to load function config")

	// ErrConfigCertNotValid is returned when the sealing certificate in the config is not valid.
	ErrConfigCertNotValid = errors.New("cert in config is not valid")

	// ErrMissingToken is returned when the 1Password service account token is missing.
	ErrMissingToken = errors.New("missing 1Password service account token")

	// ErrMissingCert is returned when the sealing certificate is missing.
	ErrMissingCert = errors.New("missing sealing certificate")

	// ErrUnmarshalSealedSecret is returned when the SealedSecret cannot be unmarshalled.
	ErrUnmarshalSealedSecret = errors.New("error unmarshalling SealedSecret")

	// ErrResolveSecret is returned when the secret cannot be resolved from 1Password.
	ErrResolveSecret = errors.New("error resolving secret from 1Password")

	// ErrProcessSealedSecret is returned when there is an error processing a SealedSecret.
	ErrProcessSealedSecret = errors.New("error processing SealedSecret")

	// ErrEncryptSecret is returned when there is an error encrypting a secret.
	ErrEncryptSecret = errors.New("error encrypting secret")
)

// Validate validates the function configuration. This is run automatically by the framework library.
func (c Config) Validate() error {
	var errs []error

	if c.Token == "" {
		errs = append(errs, ErrMissingToken)
	}

	if c.CertString == "" {
		errs = append(errs, ErrMissingCert)
	}

	return errors.Join(errs...)
}

// Cert returns the sealing certificate from the configuration.
func (c Config) Cert() (*rsa.PublicKey, error) {
	cert, err := kubeseal.ParseKey(bytes.NewReader([]byte(c.CertString)))
	if err != nil {
		return nil, errors.Join(ErrConfigCertNotValid, err)
	}

	return cert, nil
}

func isSealedSecret(node *yaml.RNode) bool {
	meta, err := node.GetValidatedMetadata()
	if err != nil {
		return false
	}

	return meta.Kind == "SealedSecret"
}

// Process processes the input ResourceList.
//
//nolint:funlen
func (p Processor) Process(input *framework.ResourceList) error {
	var cfg Config

	slog.DebugContext(p.ctx, "loading function config", "input", input, "cfg", input.FunctionConfig)

	err := framework.LoadFunctionConfig(input.FunctionConfig, &cfg)
	if err != nil {
		return errors.Join(ErrLoadConfig, err)
	}

	slog.DebugContext(p.ctx, "loaded config", "token", cfg.Token, "certString", cfg.CertString)

	slog.DebugContext(p.ctx, "ensuring 1Password client")

	client, err := ensureStore(p.ctx, p.client, cfg.Token)
	if err != nil {
		slog.ErrorContext(p.ctx, "error ensuring 1Password client", "err", err)

		return err
	}

	slog.DebugContext(p.ctx, "parsing cert")

	cert, err := cfg.Cert()
	if err != nil {
		return err
	}

	slog.DebugContext(p.ctx, "processing resource list", "itemCount", len(input.Items))

	for idx := range input.Items {
		resource := input.Items[idx]
		slog.DebugContext(
			p.ctx, "decoding resource", "idx", idx, "kind", resource.GetKind(),
			"name", resource.GetName(), "namespace", resource.GetNamespace(),
		)

		if !isSealedSecret(resource) {
			slog.DebugContext(p.ctx, "resource is not a SealedSecret", "idx", idx)

			continue
		}

		if err != nil {
			return errors.Join(ErrUnmarshalSealedSecret, err)
		}

		encryptedDataNode, err := resource.Pipe(yaml.Lookup("spec", "encryptedData"))
		if err != nil {
			slog.ErrorContext(p.ctx, "cannot retrieve spec.encryptedData", "name", resource.GetName(), "err", err.Error())

			return errors.Join(ErrProcessSealedSecret, err)
		}

		if encryptedDataNode.IsNilOrEmpty() {
			slog.DebugContext(p.ctx, "encryptedData is empty")

			continue
		}

		// TODO: Allow configurable scopes
		err = encryptedDataNode.VisitFields(
			resolveSecretFunc(
				p.ctx, client, p.randSrc,
				resource.GetName(), resource.GetNamespace(), ssv1alpha1.NamespaceWideScope, cert,
			),
		)
		if err != nil {
			return errors.Join(ErrProcessSealedSecret, err)
		}
	}

	return nil
}

func resolveSecretFunc(
	ctx context.Context,
	store secretsstore.SecretsStore,
	randSrc io.Reader,
	secretName, secretNamespace string,
	scope ssv1alpha1.SealingScope,
	sealingCert *rsa.PublicKey,
) func(*yaml.MapNode) error {
	return func(mapNode *yaml.MapNode) error {
		key := strings.TrimSpace(mapNode.Key.MustString())
		value := strings.TrimSpace(mapNode.Value.MustString())
		slog.DebugContext(ctx, "resolveSecretFunc", "key", key, "value", value)

		if value == "op://Vault Name/secret" {
			slog.DebugContext(ctx, "matches")
		}

		ref, err := SecretReferenceFromString(ctx, value)
		// Assume that data fields that aren't secret references are already encrypted values. This allows
		// mixing and matching directly sealed values with 1Password references, even within the same SealedSecret.
		if errors.Is(err, ErrInvalidSecretReference) {
			slog.DebugContext(ctx, "skipping non-secret reference", "key", key, "err", err)

			return nil
		} else if err != nil {
			return err
		}

		secret, err := store.Resolve(ctx, ref.String())
		if err != nil {
			return errors.Join(ErrResolveSecret, err)
		}

		sealedSecret, err := sealSecret(randSrc, secretName, secretNamespace, []byte(secret), scope, sealingCert)
		if err != nil {
			return errors.Join(ErrEncryptSecret, err)
		}

		slog.DebugContext(ctx, "setting secret")

		mapNode.Value.SetYNode(&yaml.Node{Kind: yaml.ScalarNode, Value: sealedSecret})

		return nil
	}
}

//nolint:ireturn
func ensureStore(
	ctx context.Context, store secretsstore.SecretsStore, token string,
) (secretsstore.SecretsStore, error) {
	if store == nil {
		slog.InfoContext(ctx, "creating new 1Password client")

		newStore, err := secretsstore.NewOnePasswordStore(ctx, token)
		if err != nil {
			//nolint:wrapcheck
			return nil, err
		}

		return newStore, nil
	}

	return store, nil
}

// NewProcessor creates a new Processor with the given options.
func NewProcessor(opts ...ProcessorOption) Processor {
	proc := &Processor{
		ctx:     context.Background(),
		randSrc: rand.Reader,
	}

	for _, opt := range opts {
		opt(proc)
	}

	return *proc
}

// WithContext sets the context for the Processor.
func WithContext(ctx context.Context) ProcessorOption {
	return func(p *Processor) {
		p.ctx = ctx
	}
}

// WithSecretsStore sets the 1Password client for the Processor.
func WithSecretsStore(client secretsstore.SecretsStore) ProcessorOption {
	return func(p *Processor) {
		p.client = client
	}
}

// WithRandSrc sets the source of random bytes for crypto operations for the Processor.
func WithRandSrc(randSrc io.Reader) ProcessorOption {
	return func(p *Processor) {
		p.randSrc = randSrc
	}
}

func sealSecret(
	randSrc io.Reader,
	secretName, secretNamespace string,
	data []byte,
	scope ssv1alpha1.SealingScope,
	pubKey *rsa.PublicKey,
) (string, error) {
	label := ssv1alpha1.EncryptionLabel(secretNamespace, secretName, scope)

	out, err := crypto.HybridEncrypt(randSrc, pubKey, data, label)
	if err != nil {
		return "", errors.Join(ErrEncryptSecret, err)
	}

	return base64.StdEncoding.EncodeToString(out), nil
}
