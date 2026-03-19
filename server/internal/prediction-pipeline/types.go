package predictionpipeline

type GeoIP struct {
	CountryName  string `json:"country_name"`
	CountryCode2 string `json:"country_code"`
}

type Os struct {
	Name    string `json:"name"`
	Full    string `json:"full"`
	Version string `json:"version"`
}

type Device struct {
	Name string `json:"name"`
}

type UserAgent struct {
	Name    string `json:"name"`
	Os      Os     `json:"os"`
	Version string `json:"version"`
	Device  Device `json:"device"`
}

type Ecs struct {
	Version string `json:"version"`
}

type Cookies struct {
	DeflectCookie         string `json:"deflectCookie"`
	SessionCookie         string `json:"sessionCookie"`
	ChallengeCookie       string `json:"challengeCookie"`
	ChallengePassedCookie string `json:"challengePassedCookie"`
}

type JsDetection struct {
	Passed bool `json:"passed"`
}

type BotManagement struct {
	Score               int         `json:"score"`
	VerifiedBot         bool        `json:"verifiedBot"`
	StaticResource      bool        `json:"staticResource"`
	CorporateProxy      bool        `json:"corporateProxy"`
	VerifiedBotCategory string      `json:"verifiedBotCategory"`
	BotDetectionIds     []int       `json:"botDetectionIds"`
	JsDetection         JsDetection `json:"js_detection"`
}

type TlsExportedAuthenticator struct {
	ClientFinished  string `json:"clientFinished"`
	ClientHandshake string `json:"clientHandshake"`
	ServerHandshake string `json:"serverHandshake"`
	ServerFinished  string `json:"serverFinished"`
}

type RequestPriority struct {
	Weight      int `json:"weight"`
	Exclusive   int `json:"exclusive"`
	Group       int `json:"group"`
	GroupWeight int `json:"groupWeight"`
}

type ClientAcceptEncoding struct {
	Gzip    bool `json:"gzip"`
	Deflate bool `json:"deflate"`
	Br      bool `json:"br"`
	Zstd    bool `json:"zstd"`
}

type CloudflareProperties struct {
	Keepalive                  bool                     `json:"keepalive"`
	Asn                        int                      `json:"asn"`
	AsOrganization             string                   `json:"asOrganization"`
	BotManagement              BotManagement            `json:"botManagement"`
	City                       string                   `json:"city"`
	ClientAcceptEncoding       ClientAcceptEncoding     `json:"clientAcceptEncoding"`
	ClientTcpRtt               string                   `json:"clientTcpRtt"`
	CloudflareDatacenterCode   string                   `json:"cloudflare_datacenter_code"`
	Continent                  string                   `json:"continent"`
	Country                    string                   `json:"country"`
	EdgeRequestKeepAliveStatus int                      `json:"edgeRequestKeepAliveStatus"`
	HttpProtocol               string                   `json:"httpProtocol"`
	IsEUCountry                string                   `json:"isEUCountry"`
	Latitude                   string                   `json:"latitude"`
	Longitude                  string                   `json:"longitude"`
	PostalCode                 string                   `json:"postalCode"`
	Region                     string                   `json:"region"`
	RegionCode                 string                   `json:"regionCode"`
	RequestPriority            RequestPriority          `json:"request_priority"`
	Timezone                   string                   `json:"timezone"`
	TlsCipher                  string                   `json:"tlsCipher"`
	TlsExportedAuthenticator   TlsExportedAuthenticator `json:"tlsExportedAuthenticator"`
	TlsVersion                 string                   `json:"tlsVersion"`
}

type WorkerRequest struct {
	RequestType               string               `json:"request_type"`
	Language                  string               `json:"language"`
	ClientAcceptedEncoding    string               `json:"client_accepted_encoding"`
	CloudflareRay             string               `json:"cloudflare_ray"`
	DoNotTrack                string               `json:"do_not_track"`
	IsDirectTraffic           bool                 `json:"is_direct_traffic"`
	RequestOriginationType    string               `json:"request_origination_type"`
	RequestMode               string               `json:"request_mode"`
	RequestDestinationType    string               `json:"request_destination_type"`
	IsConditionalGet          bool                 `json:"is_conditional_get"`
	Cookies                   Cookies              `json:"cookies"`
	HttpRequestScheme         string               `json:"http_request_scheme"`
	ClientRequestMethod       string               `json:"client_request_method"`
	Datestamp                 string               `json:"datestamp"`
	GeoIP                     GeoIP                `json:"geoip"`
	HttpResponseCode          int                  `json:"http_response_code"`
	ReplyLengthBytes          string               `json:"reply_length_bytes"`
	HttpRequestVersion        string               `json:"http_request_version"`
	UserAgent                 UserAgent            `json:"user_agent"`
	ClientUserAgent           string               `json:"client_user_agent"`
	Ecs                       Ecs                  `json:"ecs"`
	ClientIp                  string               `json:"client_ip"`
	ClientUrl                 string               `json:"client_url"`
	ContentType               string               `json:"content_type"`
	ClientRequestHostOriginal string               `json:"client_request_host_original"`
	CacheResult               string               `json:"cache_result"`
	ClientRequestHost         string               `json:"client_request_host"`
	Querystring               string               `json:"querystring"`
	CloudflareProperties      CloudflareProperties `json:"cloudflareProperties"`
}
