package ttp

// k_series_stub.go -- Windows kernel stealth status via Nidhogg
//
// Replaces the Linux K-series stub. Reports Nidhogg driver status
// to the bat-server instead of a generic skip message.
// When TTP 1000 loads the driver, LocalStealthStatus() reflects it.

// LocalStealthStatus reports Windows stealth status.
// Returns Nidhogg active status if driver is loaded, skip otherwise.
func LocalStealthStatus() string {
	return NidhoggLocalStealthStatus()
}

// StartKSeries is a no-op on Windows (Nidhogg loaded via TTP 1000).
func StartKSeries(_, _, _, _ string) {}

// TakePendingStealthReport returns (0, "") on Windows (no async K-series probes).
func TakePendingStealthReport() (int, string) { return 0, "" }
