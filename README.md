# CloudTrail DuckDB JSON Analyzer

## Project Structure

```
ct-ddb-json/
├── .spec/                  # Specification documents
├── src/
│   ├── common/            # Shared utilities and configurations
│   ├── phase1/            # S3 to EC2 data pipeline
│   └── phase2/            # DuckDB query engine (coming soon)
├── tests/                 # Unit and integration tests
├── notebooks/             # Jupyter notebooks for interaction
├── data/                  # Local data storage
│   ├── raw/              # Downloaded gz files
│   ├── processed/        # Decompressed JSON files
│   └── reports/          # Integrity and analysis reports
└── requirements.txt       # Python dependencies
```

## Using Amazon Q CLI

once u load the Cloudtrail logs, configure Q CLI on machine and run the following in the root directory of the project

> q chat


> the Data/processed folder from current directior contains the CloudTrail logs copied from S3 bucket and decompressed into JSON format keeping the consistent folder structure of AWSLogs/account-id/CloudTrail/region/year/month/date. This project contains 2 phases , Phase 1 is about fetching logs from s3 into local directory and extracting the .gz format and phase 2 contains DuckDB approach to query the json format. USe this information and use DuckDB to help me answer the queries related to account ID <use-your-account-id> , for cloudtrail logs between <july 25 to 31>. validate you have all the information and Wait for me to ask additional questions.