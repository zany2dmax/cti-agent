package enrich

// The product names are internal/product's; these keep enrich's own names
// for them, which its callers and tests use.

import "github.com/zany2dmax/cti-agent/internal/product"

// nvdConfigurations is the part of an NVD CVE record CPEProducts reads.
type nvdConfigurations = product.Configurations

// ProductName is product.Name.
func ProductName(vendor, name string) string { return product.Name(vendor, name) }

// CPEProducts is product.CPEProducts.
func CPEProducts(conf nvdConfigurations) [][]string { return product.CPEProducts(conf) }

// ProductFromTitle is product.FromTitle.
func ProductFromTitle(title string) string { return product.FromTitle(title) }

// ProductFor is product.For.
func ProductFor(kevVendor, kevProduct string, cpe [][]string, titles []string, provider string) (string, string) {
	return product.For(kevVendor, kevProduct, cpe, titles, provider)
}
