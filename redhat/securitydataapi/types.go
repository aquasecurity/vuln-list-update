package securitydataapi

import (
	"encoding/json"

	"golang.org/x/xerrors"
)

type RedhatEntry struct {
	CveID string `json:"CVE"`
}

type RedhatCVEJSON struct {
	ThreatSeverity       string                  `json:"threat_severity"`
	PublicDate           string                  `json:"public_date"`
	Bugzilla             RedhatBugzilla          `json:"bugzilla"`
	Cvss                 RedhatCvss              `json:"cvss"`
	Cvss3                RedhatCvss3             `json:"cvss3"`
	Iava                 string                  `json:"iava"`
	Cwe                  string                  `json:"cwe"`
	Statement            string                  `json:"statement"`
	Acknowledgement      string                  `json:"acknowledgement"`
	Mitigation           string                  `json:"-"`
	AffectedRelease      []RedhatAffectedRelease `json:"-"`
	PackageState         []RedhatPackageState    `json:"-"`
	Name                 string                  `json:"name"`
	DocumentDistribution string                  `json:"document_distribution"`

	Details    []string `json:"details"`
	References []string `json:"references"`
}

func (r *RedhatCVEJSON) UnmarshalJSON(data []byte) error {
	type AliasRedhatCVEJSON RedhatCVEJSON
	alias := &struct {
		TempMitigation      interface{} `json:"mitigation"`       // mitigation is string or object
		TempAffectedRelease interface{} `json:"affected_release"` // affected_release is array or object
		TempPackageState    interface{} `json:"package_state"`    // package_state is array or object
		*AliasRedhatCVEJSON
	}{
		AliasRedhatCVEJSON: (*AliasRedhatCVEJSON)(r),
	}

	if err := json.Unmarshal(data, alias); err != nil {
		return err
	}

	switch alias.TempAffectedRelease.(type) {
	case []interface{}:
		var ar RedhatCVEJSONAffectedReleaseArray
		if err := json.Unmarshal(data, &ar); err != nil {
			return xerrors.Errorf("unknown affected_release type: %w", err)
		}
		r.AffectedRelease = ar.AffectedRelease
	case map[string]interface{}:
		var ar RedhatCVEJSONAffectedReleaseObject
		if err := json.Unmarshal(data, &ar); err != nil {
			return xerrors.Errorf("unknown affected_release type: %w", err)
		}
		r.AffectedRelease = []RedhatAffectedRelease{ar.AffectedRelease}
	case nil:
	default:
		return xerrors.New("unknown affected_release type")
	}

	switch alias.TempPackageState.(type) {
	case []interface{}:
		var ps RedhatCVEJSONPackageStateArray
		if err := json.Unmarshal(data, &ps); err != nil {
			return xerrors.Errorf("unknown package_state type: %w", err)
		}
		r.PackageState = ps.PackageState
	case map[string]interface{}:
		var ps RedhatCVEJSONPackageStateObject
		if err := json.Unmarshal(data, &ps); err != nil {
			return xerrors.Errorf("unknown package_state type: %w", err)
		}
		r.PackageState = []RedhatPackageState{ps.PackageState}
	case nil:
	default:
		return xerrors.New("unknown package_state type")
	}

	switch alias.TempMitigation.(type) {
	case string:
		r.Mitigation = alias.TempMitigation.(string)
	case map[string]interface{}:
		var m struct {
			Mitigation RedhatCVEJSONMitigationObject
		}
		if err := json.Unmarshal(data, &m); err != nil {
			return xerrors.Errorf("unknown mitigation type: %w", err)
		}
		r.Mitigation = m.Mitigation.Value
	case nil:
	default:
		return xerrors.New("unknown mitigation type")
	}

	return nil
}

func (r *RedhatCVEJSON) MarshalJSON() ([]byte, error) {
	type Alias RedhatCVEJSON
	return json.Marshal(&struct {
		TempMitigation      string      `json:"mitigation,omitempty"`
		TempAffectedRelease interface{} `json:"affected_release,omitempty"` // affected_release is array or object
		TempPackageState    interface{} `json:"package_state,omitempty"`    // package_state is array or object
		*Alias
	}{
		TempMitigation:      r.Mitigation,
		TempAffectedRelease: r.AffectedRelease,
		TempPackageState:    r.PackageState,
		Alias:               (*Alias)(r),
	})
}

type RedhatCVEJSONAffectedReleaseArray struct {
	AffectedRelease []RedhatAffectedRelease `json:"affected_release"`
}

type RedhatCVEJSONAffectedReleaseObject struct {
	AffectedRelease RedhatAffectedRelease `json:"affected_release"`
}

type RedhatCVEJSONPackageStateArray struct {
	PackageState []RedhatPackageState `json:"package_state"`
}

type RedhatCVEJSONPackageStateObject struct {
	PackageState RedhatPackageState `json:"package_state"`
}

type RedhatCVEJSONMitigationObject struct {
	Value string
	Lang  string
}

type RedhatDetail struct {
	RedhatCVEID int64 `json:",omitempty"`
	Detail      string
}

type RedhatReference struct {
	RedhatCVEID int64 `json:",omitempty"`
	Reference   string
}

type RedhatBugzilla struct {
	RedhatCVEID int64  `json:",omitempty"`
	Description string `json:"description"`

	BugzillaID string `json:"id"`
	URL        string `json:"url"`
}

type RedhatCvss struct {
	RedhatCVEID       int64  `json:",omitempty"`
	CvssBaseScore     string `json:"cvss_base_score"`
	CvssScoringVector string `json:"cvss_scoring_vector"`
	Status            string `json:"status"`
}

type RedhatCvss3 struct {
	RedhatCVEID        int64  `json:",omitempty"`
	Cvss3BaseScore     string `json:"cvss3_base_score"`
	Cvss3ScoringVector string `json:"cvss3_scoring_vector"`
	Status             string `json:"status"`
}

type RedhatAffectedRelease struct {
	RedhatCVEID int64  `json:",omitempty"`
	ProductName string `json:"product_name"`
	ReleaseDate string `json:"release_date"`
	Advisory    string `json:"advisory"`
	Package     string `json:"package"`
	Cpe         string `json:"cpe"`
}

type RedhatPackageState struct {
	RedhatCVEID int64  `json:",omitempty"`
	ProductName string `json:"product_name"`
	FixState    string `json:"fix_state"`
	PackageName string `json:"package_name"`
	Cpe         string `json:"cpe"`
}
