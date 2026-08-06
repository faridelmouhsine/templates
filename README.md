You are a Senior DevSecOps Engineer and Azure DevOps Governance expert.

Your objective is to build a complete Python solution that inventories Azure DevOps projects and repositories associated with a list of CXOne applications and produces a governance report.

## Context

I have:

- Azure DevOps Organization
- A Personal Access Token (PAT)
- A list of CXOne applications

I need to determine why these applications are not onboarded in CXOne by discovering their Azure DevOps assets.

The goal is NOT only to list repositories.

The goal is to perform a governance assessment.

---------------------------------------------------------
INPUT FILES
---------------------------------------------------------

The project contains:

pat.txt
-------------
Contains ONLY the Azure DevOps Personal Access Token.

organization.txt
----------------
Contains the Azure DevOps organization URL.

Example:

https://dev.azure.com/axafrance

applications.txt
----------------
Contains one CXOne application name per line.

Example

Proxy AXA Banque
API SALESFORCE - Automatisation des habilitations
BASE MANDAT
CASIER CONNECTE
Cockpit SA portail d'évaluation
Decision Center
Evoko Home
GDS
Geomarketing
ISA
Lex Files
Livedocs
MES PERSONAS
MIA_DISCOVERY_WEB
OSE Cyber
Spid

---------------------------------------------------------
AUTHENTICATION
---------------------------------------------------------

Read the PAT ONLY from pat.txt.

Never hardcode it.

Never print it.

Use Basic Authentication against Azure DevOps REST API.

---------------------------------------------------------
SEARCH STRATEGY
---------------------------------------------------------

For EACH application:

1. Search Azure DevOps Projects.

The search should not rely only on exact names.

Use:

- exact match
- contains
- startswith
- fuzzy similarity

If multiple projects are found,
keep all of them.

---------------------------------------------------------
FOR EACH PROJECT
---------------------------------------------------------

Retrieve

- Project Name
- Project ID
- Project URL
- Last update date

---------------------------------------------------------
FOR EACH REPOSITORY
---------------------------------------------------------

Retrieve

Repository Name

Repository ID

Repository URL

Default Branch

Repository Size (if available)

Repository Status

Disabled

Archived

Active

Is Fork

Remote URL

---------------------------------------------------------
LATEST ACTIVITY
---------------------------------------------------------

Retrieve

Latest Commit Date

Latest Commit Author

Latest Commit Email

Latest Commit Message

Commit SHA

Number of branches

---------------------------------------------------------
PIPELINES
---------------------------------------------------------

Determine whether

Classic Build Pipeline exists

YAML Pipeline exists

Release Pipeline exists

Last Pipeline Run

Pipeline Status

---------------------------------------------------------
REPOSITORY CLASSIFICATION
---------------------------------------------------------

Automatically classify every repository as

Application Source Code

Infrastructure as Code

Shared Library

Configuration

Documentation

Templates

Archive

Unknown

Use repository names and file structure when possible.

---------------------------------------------------------
GOVERNANCE ANALYSIS
---------------------------------------------------------

For every repository determine

Repository Active

YES / NO

Last Commit older than 12 months

YES / NO

Likely obsolete

YES / NO

Contains application code

YES / NO

Candidate for SAST

YES / NO

Candidate for SCA

YES / NO

Candidate for DAST

YES / NO

Needs Application Owner validation

YES / NO

---------------------------------------------------------
ONBOARDING SCORE
---------------------------------------------------------

Calculate an onboarding score.

Example

Recent commits

+20

Application code detected

+20

Pipeline exists

+20

Repository active

+20

Repository not archived

+20

Score

0-100

Recommendation

80-100

High Priority

50-79

Medium Priority

0-49

Low Priority

---------------------------------------------------------
OUTPUT
---------------------------------------------------------

Generate an Excel workbook named

CXOne_AzureDevOps_Governance.xlsx

Sheet 1

Executive Summary

Include

Total Applications

Projects Found

Repositories Found

Repositories Active

Repositories Archived

Repositories Disabled

Repositories without activity >12 months

Repositories with pipelines

Repositories without pipelines

High Priority candidates

Medium Priority candidates

Low Priority candidates

---------------------------------------------------------

Sheet 2

Applications Summary

Application

Projects Found

Repositories Found

Last Activity

Governance Status

Recommendation

---------------------------------------------------------

Sheet 3

Projects

Application

Azure DevOps Project

Project ID

Repositories Count

---------------------------------------------------------

Sheet 4

Repositories Inventory

Application

Project

Repository

Repository URL

Repository Type

Status

Default Branch

Last Commit Date

Last Commit Author

Commit Message

Branches

Pipeline

Last Pipeline

Repository Classification

SAST Candidate

SCA Candidate

DAST Candidate

Onboarding Score

Recommendation

---------------------------------------------------------

Sheet 5

Repositories Requiring Investigation

Include only repositories with

No commits >12 months

No pipeline

Unknown classification

Archived

Disabled

No activity

---------------------------------------------------------

Sheet 6

Dashboard

Create charts showing

Repositories by Status

Repositories by Classification

Repositories by Recommendation

Applications by Number of Repositories

Pipeline Coverage

Repository Activity

---------------------------------------------------------

TECHNICAL REQUIREMENTS

Use Python 3.

Use

requests

openpyxl

pandas

tqdm

Implement logging.

Handle API pagination.

Handle HTTP errors.

Retry transient failures.

Do not stop if one application fails.

Continue processing.

At the end produce

1. Excel report

2. CSV export

3. JSON export

4. Console summary

The code must be modular, clean, documented and production-ready.
