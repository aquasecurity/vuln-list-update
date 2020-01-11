package fedora

type Release struct {
	Name              string `json:"name"`
	LongName          string `json:"long_name"`
	Version           string `json:"version"`
	IDPrefix          string `json:"id_prefix"`
	Branch            string `json:"branch"`
	DistTag           string `json:"dist_tag"`
	StableTag         string `json:"stable_tag"`
	TestingTag        string `json:"testing_tag"`
	CandidateTag      string `json:"candidate_tag"`
	PendingSigningTag string `json:"pending_signing_tag"`
	PendingTestingTag string `json:"pending_testing_tag"`
	PendingStableTag  string `json:"pending_stable_tag"`
	OverrideTag       string `json:"override_tag"`
	State             string `json:"state"`
	PackageManager    string `json:"package_manager"`
	TestingRepository string `json:"testing_repository"`
}

type Comment struct {
	ID            int    `json:"id"`
	Karma         int    `json:"karma"`
	KarmaCritpath int    `json:"karma_critpath"`
	Text          string `json:"text"`
	Timestamp     string `json:"timestamp"`
	UpdateID      int    `json:"update_id"`
	UserID        int    `json:"user_id"`
	User          User   `json:"user"`
}

type User struct {
	ID    int    `json:"id"`
	Name  string `json:"name"`
	Email string `json:"email"`
}

type Build struct {
	Nvr       string `json:"nvr"`
	ReleaseID int    `json:"release_id"`
	Signed    bool   `json:"signed"`
	Type      string `json:"type"`
	Epoch     int    `json:"epoch"`
}

type Bug struct {
	BugID    int    `json:"bug_id"`
	Title    string `json:"title"`
	Security bool   `json:"security"`
}

type FedoraAdvisory struct {
	FedoraID         string    `json:"updateid"`
	StableKarma      int       `json:"stable_karma"`
	StableDays       int       `json:"stable_days"`
	UnstableKarma    int       `json:"unstable_karma"`
	Requirements     string    `json:"requirements"`
	DisplayName      string    `json:"display_name"`
	Notes            string    `json:"notes"`
	Status           string    `json:"status"`
	Severity         string    `json:"severity"`
	Suggest          string    `json:"suggest"`
	CloseBugs        bool      `json:"close_bugs"`
	DateSubmitted    string    `json:"date_submitted"`
	DatePushed       string    `json:"date_pushed"`
	DateTesting      string    `json:"date_testing"`
	Alias            string    `json:"alias"`
	TestGatingStatus string    `json:"test_gating_status"`
	URL              string    `json:"url"`
	Title            string    `json:"title"`
	VersionHash      string    `json:"version_hash"`
	Release          Release   `json:"release"`
	Comments         []Comment `json:"comments"`
	Builds           []Build   `json:"builds"`
	Bugs             []Bug     `json:"bugs"`
	Karma            int       `json:"karma"`
	ContentType      string    `json:"content_type"`
}

type FedoraAdvisoriesPagenation struct {
	FedoraAdvisories []FedoraAdvisory `json:"updates"`
	Page             int              `json:"page"`
	Pages            int              `json:"pages"`
	RowsPerPage      int              `json:"rows_per_page"`
	Total            int              `json:"total"`
}
