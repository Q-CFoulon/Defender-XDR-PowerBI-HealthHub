let
    BaseUrl = "http://localhost:4010/api/powerbi",

    ProgramInitiatives = Json.Document(Web.Contents(BaseUrl, [RelativePath = "program-initiatives"])),
    ProgramInitiativesTable = Table.FromRecords(ProgramInitiatives),

    TopInitiatives = Json.Document(Web.Contents(BaseUrl, [RelativePath = "top-initiatives"])),
    TopInitiativesTable = Table.FromRecords(TopInitiatives),

    SecureScores = Json.Document(Web.Contents(BaseUrl, [RelativePath = "secure-scores"])),
    SecureScoresTable = Table.FromRecords({SecureScores}),

    VulnerabilityOverview = Json.Document(Web.Contents(BaseUrl, [RelativePath = "vulnerability-overview"])),
    VulnerabilityOverviewTable = Table.FromRecords({VulnerabilityOverview}),

    RemediationRecommendations = Json.Document(Web.Contents(BaseUrl, [RelativePath = "remediation-recommendations"])),
    RemediationRecommendationsTable = Table.FromRecords(RemediationRecommendations)
in
    [
        ProgramInitiatives = ProgramInitiativesTable,
        TopInitiatives = TopInitiativesTable,
        SecureScores = SecureScoresTable,
        VulnerabilityOverview = VulnerabilityOverviewTable,
        RemediationRecommendations = RemediationRecommendationsTable
    ]
