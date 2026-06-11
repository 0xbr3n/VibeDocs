"""Seed new library findings: SQLi, SSRF, SSTI, CSV Injection, LFI/RFI,
Lack of Input Sanitisation, Lack of Rate Limiting, User Enumeration,
Verbose Errors, Hardcoded Secrets in Lambda.
Run with: python3 seed_findings_new.py
"""
import sys
sys.path.insert(0, '/app')
from app.database import SessionLocal
from app.models import FindingLibrary

db = SessionLocal()

WEB = 1   # web_vapt template_id
AWS = 10  # aws_cloud_vapt


def add(title, severity, cvss_score, cvss_vector, cwe, owasp,
        description, impact, remediation, references, tags, template_id=WEB):
    if db.query(FindingLibrary).filter(FindingLibrary.title == title).first():
        print(f"SKIP (exists): {title!r}")
        return
    f = FindingLibrary(
        template_id=template_id,
        title=title,
        default_severity=severity,
        default_cvss_score=cvss_score,
        default_cvss_vector=cvss_vector,
        cwe=cwe,
        owasp_category=owasp,
        description=description,
        impact=impact,
        remediation=remediation,
        references=references,
        tags=tags,
        status='approved',
        created_by_id=1,
        reviewed_by_id=1,
    )
    db.add(f)
    db.flush()
    print(f"ADDED id={f.id}: {title!r}")


# ------------------------------------------------------------------
# 1. SQL Injection
# ------------------------------------------------------------------
add(
    title='SQL Injection',
    severity='Critical',
    cvss_score=9.3,
    cvss_vector='CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N',
    cwe='CWE-89 (Improper Neutralisation of Special Elements used in an SQL Command)',
    owasp='A03:2021',
    description=(
        'The application was found to be vulnerable to SQL Injection (SQLi). '
        'User-supplied input was passed directly to database queries without sufficient '
        'sanitisation or parameterisation. An attacker can manipulate the SQL query to '
        'retrieve, modify, or delete data from the backend database, bypass authentication '
        'mechanisms, and in some configurations execute operating-system commands via '
        'database-level functionality (e.g., xp_cmdshell on MSSQL).'
    ),
    impact=(
        'Successful exploitation can lead to full unauthorised access to the application '
        'database, disclosure of all stored data (credentials, PII, business records), '
        'authentication bypass, data tampering, and potential server compromise if the '
        'database account has elevated operating-system privileges.'
    ),
    remediation=(
        'Use parameterised queries or prepared statements for all database interactions. '
        'Employ an ORM layer that handles query construction safely. '
        'Apply input validation and allowlisting for fields where only specific formats are '
        'expected. Enforce least-privilege database accounts. Enable a Web Application '
        'Firewall (WAF) as a defence-in-depth control. Review and sanitise all existing '
        'dynamic SQL constructs in the codebase.'
    ),
    references=(
        '- https://owasp.org/www-community/attacks/SQL_Injection\n'
        '- https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html\n'
        '- CWE-89: https://cwe.mitre.org/data/definitions/89.html'
    ),
    tags=['owasp', 'cwe-89', 'a03:2021', 'sqli', 'injection',
          'web_vapt', 'template:web_vapt', 'template:api_vapt'],
)

# ------------------------------------------------------------------
# 2. SSRF
# ------------------------------------------------------------------
add(
    title='Server-Side Request Forgery (SSRF)',
    severity='High',
    cvss_score=8.7,
    cvss_vector='CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N',
    cwe='CWE-918 (Server-Side Request Forgery)',
    owasp='A10:2021',
    description=(
        'The application was found to be vulnerable to Server-Side Request Forgery (SSRF). '
        'A user-controlled parameter was used by the server to construct and execute an '
        'outbound HTTP request without adequate restriction. An attacker can supply an '
        'arbitrary URL or IP address to cause the server to make requests to internal '
        'services, cloud metadata endpoints (e.g., http://169.254.169.254/), or '
        'attacker-controlled external systems.'
    ),
    impact=(
        'Exploitation can allow an attacker to enumerate internal network services, '
        'access cloud instance metadata (including IAM credentials on AWS/Azure/GCP), '
        'pivot to internal systems not directly reachable from the internet, and '
        'exfiltrate sensitive configuration data.'
    ),
    remediation=(
        'Validate and allowlist the set of URLs or IP ranges the application is permitted '
        'to contact. Reject requests targeting private IP ranges (RFC 1918), loopback, '
        'and link-local addresses. Disable unnecessary URL-fetching functionality. '
        'Use a dedicated egress proxy that enforces allowlisting. Disable HTTP redirects '
        'or validate redirect destinations before following. On cloud environments, '
        'restrict access to the metadata endpoint via network-level controls (e.g., IMDSv2 '
        'on AWS).'
    ),
    references=(
        '- https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/\n'
        '- https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html\n'
        '- CWE-918: https://cwe.mitre.org/data/definitions/918.html'
    ),
    tags=['owasp', 'cwe-918', 'a10:2021', 'ssrf',
          'web_vapt', 'template:web_vapt', 'template:api_vapt'],
)

# ------------------------------------------------------------------
# 3. SSTI
# ------------------------------------------------------------------
add(
    title='Server-Side Template Injection (SSTI)',
    severity='Critical',
    cvss_score=9.3,
    cvss_vector='CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N',
    cwe='CWE-94 (Improper Control of Generation of Code)',
    owasp='A03:2021',
    description=(
        'The application was found to be vulnerable to Server-Side Template Injection (SSTI). '
        'User-supplied input was embedded directly into a server-side template (e.g., '
        'Jinja2, Twig, FreeMarker, Pebble) and rendered without sanitisation. An attacker '
        'can inject template expressions that are evaluated by the template engine, '
        'potentially achieving arbitrary code execution on the server.'
    ),
    impact=(
        'Successful exploitation of SSTI can lead to remote code execution (RCE) on the '
        'server, full compromise of the hosting environment, access to environment '
        'variables and secrets, lateral movement within the internal network, and '
        'complete data exfiltration.'
    ),
    remediation=(
        'Never concatenate untrusted user input into template strings. Use a logic-less '
        'template engine where possible, or strictly separate data from template logic. '
        'Render user-supplied content as data (not template code) by passing it through '
        'the template context, not by embedding it in the template source. Apply '
        'sandboxing if the template engine supports it (e.g., Jinja2 SandboxedEnvironment). '
        'Perform regular code reviews for dynamic template construction patterns.'
    ),
    references=(
        '- https://portswigger.net/web-security/server-side-template-injection\n'
        '- https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/18-Testing_for_Server_Side_Template_Injection\n'
        '- CWE-94: https://cwe.mitre.org/data/definitions/94.html'
    ),
    tags=['owasp', 'cwe-94', 'a03:2021', 'ssti', 'rce', 'injection',
          'web_vapt', 'template:web_vapt', 'template:api_vapt'],
)

# ------------------------------------------------------------------
# 4. CSV Injection
# ------------------------------------------------------------------
add(
    title='CSV Injection (Formula Injection)',
    severity='Medium',
    cvss_score=5.1,
    cvss_vector='CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:P/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N',
    cwe='CWE-1236 (Improper Neutralisation of Formula Elements in a CSV File)',
    owasp='A03:2021',
    description=(
        'The application was found to include user-supplied input in exported CSV files '
        'without sanitising formula characters. Fields beginning with =, +, -, or @ are '
        'interpreted as spreadsheet formulas by Microsoft Excel and LibreOffice Calc when '
        'the file is opened. An attacker can craft input that executes arbitrary formulas, '
        'including Dynamic Data Exchange (DDE) commands that can execute OS-level commands '
        'on the victim machine when the exported CSV is opened.'
    ),
    impact=(
        'A malicious user who controls exported data can cause arbitrary formula execution '
        'on the machine of any user who opens the exported file. In the worst case, '
        'DDE-based payloads can execute OS commands on the victim machine. This primarily '
        'affects internal users (analysts, management) who receive and open exported reports.'
    ),
    remediation=(
        "Prefix any field that begins with =, +, -, or @ with a single quote (') or a "
        'tab character before including it in CSV output. Alternatively, wrap all fields '
        'in double quotes and escape internal double quotes. Consider adding a server-side '
        'allowlist for characters in fields that are exported. Where possible, export to '
        'a safer format (e.g., XLSX with no formula interpretation).'
    ),
    references=(
        '- https://owasp.org/www-community/attacks/CSV_Injection\n'
        '- CWE-1236: https://cwe.mitre.org/data/definitions/1236.html\n'
        '- https://www.contextis.com/en/blog/comma-separated-vulnerabilities'
    ),
    tags=['owasp', 'cwe-1236', 'a03:2021', 'csv-injection', 'formula-injection',
          'web_vapt', 'template:web_vapt', 'template:api_vapt'],
)

# ------------------------------------------------------------------
# 5. LFI / RFI
# ------------------------------------------------------------------
add(
    title='Local File Inclusion / Remote File Inclusion (LFI/RFI)',
    severity='High',
    cvss_score=8.7,
    cvss_vector='CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N',
    cwe='CWE-98 (Improper Control of Filename for Include/Require Statement)',
    owasp='A03:2021',
    description=(
        'The application was found to be vulnerable to File Inclusion. A user-controlled '
        'parameter was used to determine which file is included or loaded by the server. '
        'Local File Inclusion (LFI) allows an attacker to read arbitrary files on the '
        'server filesystem, including configuration files and sensitive credentials. '
        'Remote File Inclusion (RFI) extends this to loading attacker-controlled remote '
        'files, which can result in remote code execution.'
    ),
    impact=(
        'LFI can expose sensitive server-side files such as /etc/passwd, application '
        'configuration files, database credentials, private keys, and source code. '
        'RFI can result in full remote code execution, allowing an attacker to deploy '
        'web shells and achieve persistent access to the server.'
    ),
    remediation=(
        'Avoid using user-supplied input to determine which files are included. If file '
        'selection is required, use an allowlist of permitted filenames mapped to a lookup '
        'table. Disable PHP allow_url_include and allow_url_fopen directives to prevent '
        'RFI. Apply input validation to reject path traversal sequences (../, ..\\). '
        'Store includable files outside the web root and reference them by index, not '
        'by path. Enforce least-privilege file system permissions on the web server '
        'account.'
    ),
    references=(
        '- https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion\n'
        '- CWE-98: https://cwe.mitre.org/data/definitions/98.html\n'
        '- https://owasp.org/www-community/attacks/Path_Traversal'
    ),
    tags=['owasp', 'cwe-98', 'a03:2021', 'lfi', 'rfi', 'path-traversal',
          'web_vapt', 'template:web_vapt', 'template:api_vapt'],
)

# ------------------------------------------------------------------
# 6. Lack of Input Sanitisation
# ------------------------------------------------------------------
add(
    title='Lack of Input Sanitisation',
    severity='Medium',
    cvss_score=5.1,
    cvss_vector='CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N',
    cwe='CWE-20 (Improper Input Validation)',
    owasp='A03:2021',
    description=(
        'The application was observed to accept and process user-supplied input without '
        'adequate validation or sanitisation. Input fields accepted unexpected character '
        'sets, special characters, excessively long strings, or data types inconsistent '
        'with the expected input format. This broad lack of input hygiene creates a '
        'surface for downstream injection attacks, unexpected application behaviour, and '
        'data integrity issues.'
    ),
    impact=(
        'Unsanitised input can be exploited as a precursor to injection attacks '
        '(XSS, SQLi, command injection), cause unexpected application errors, corrupt '
        'stored data, trigger denial-of-service conditions through malformed payloads, '
        'and undermine the trustworthiness of data processed by the system.'
    ),
    remediation=(
        'Implement server-side input validation for all user-supplied data, including '
        'type, length, format, and range. Apply allowlisting (accept known-good values) '
        'rather than blocklisting (reject known-bad values). Encode output appropriately '
        'for the context in which it is rendered (HTML, SQL, shell, etc.). Use '
        'framework-provided validation libraries and sanitisation functions. Reject and '
        'log requests containing invalid input rather than silently accepting or '
        'correcting them.'
    ),
    references=(
        '- https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html\n'
        '- CWE-20: https://cwe.mitre.org/data/definitions/20.html\n'
        '- https://owasp.org/www-project-top-ten/2021/A03_2021-Injection'
    ),
    tags=['owasp', 'cwe-20', 'a03:2021', 'input-validation', 'sanitisation',
          'web_vapt', 'template:web_vapt', 'template:api_vapt'],
)

# ------------------------------------------------------------------
# 7. Lack of Rate Limiting
# ------------------------------------------------------------------
add(
    title='Lack of Rate Limiting',
    severity='Medium',
    cvss_score=5.3,
    cvss_vector='CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N',
    cwe='CWE-770 (Allocation of Resources Without Limits or Throttling)',
    owasp='A04:2023',
    description=(
        'The application does not implement adequate rate limiting or throttling controls '
        'on sensitive endpoints. An unauthenticated or authenticated attacker can submit '
        'an unrestricted number of requests to endpoints such as login, password reset, '
        'OTP verification, or API functions without triggering any lockout or throttling '
        'mechanism. This enables brute-force attacks, credential stuffing, account '
        'enumeration, and API abuse.'
    ),
    impact=(
        'Without rate limiting, an attacker can systematically brute-force credentials or '
        'OTP values, abuse password reset flows, enumerate valid usernames or email '
        'addresses, excessively consume API quotas, and potentially cause denial-of-service '
        'conditions on the targeted endpoints.'
    ),
    remediation=(
        'Implement rate limiting on all authentication, password reset, and sensitive API '
        'endpoints. Enforce account lockout or progressive delays after a configurable '
        'number of failed attempts. Use CAPTCHA on login and registration flows after '
        'repeated failures. Apply rate limits at both the application and infrastructure '
        '(API gateway, WAF, load balancer) layers. Log and alert on anomalously high '
        'request rates to sensitive endpoints. Consider token-bucket or sliding-window '
        'algorithms for more sophisticated throttling.'
    ),
    references=(
        '- https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html\n'
        '- CWE-770: https://cwe.mitre.org/data/definitions/770.html\n'
        '- https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/'
    ),
    tags=['owasp', 'cwe-770', 'a04:2023', 'rate-limiting', 'brute-force',
          'web_vapt', 'template:web_vapt', 'template:api_vapt'],
)

# ------------------------------------------------------------------
# 8. User Enumeration
# ------------------------------------------------------------------
add(
    title='User Enumeration',
    severity='Low',
    cvss_score=2.3,
    cvss_vector='CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N',
    cwe='CWE-203 (Observable Discrepancy)',
    owasp='A01:2021',
    description=(
        'The application reveals whether a username or email address is registered through '
        'observable differences in application responses. On the login, password reset, '
        'or registration pages, the application returns distinct error messages, HTTP '
        'status codes, or response times that allow an attacker to determine whether a '
        'given account exists in the system (e.g., "Invalid password" vs "Account not '
        'found").'
    ),
    impact=(
        'User enumeration allows an attacker to compile a list of valid account '
        'identifiers, which significantly reduces the effort required for targeted '
        'brute-force attacks, credential stuffing, spear phishing, and social engineering '
        'campaigns. It also represents a privacy disclosure for systems where the '
        'existence of an account is sensitive.'
    ),
    remediation=(
        'Return generic, identical error messages for all authentication failure conditions '
        '(e.g., "Invalid username or password"). Ensure response timing is consistent '
        'regardless of whether the account exists (use constant-time comparison for '
        'credentials). Apply the same response on the password reset page regardless of '
        'whether the email is registered. Avoid exposing account existence through HTTP '
        'status codes or redirect behaviour.'
    ),
    references=(
        '- https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/03-Identity_Management_Testing/04-Testing_for_Account_Enumeration_and_Guessable_User_Account\n'
        '- CWE-203: https://cwe.mitre.org/data/definitions/203.html\n'
        '- https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html'
    ),
    tags=['owasp', 'cwe-203', 'a01:2021', 'enumeration', 'information-disclosure',
          'web_vapt', 'template:web_vapt', 'template:api_vapt'],
)

# ------------------------------------------------------------------
# 9. Verbose Error Messages
# ------------------------------------------------------------------
add(
    title='Verbose Error Messages in HTTP Response',
    severity='Low',
    cvss_score=2.3,
    cvss_vector='CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N',
    cwe='CWE-209 (Generation of Error Message Containing Sensitive Information)',
    owasp='A05:2021',
    description=(
        'The application was observed to return verbose error messages in HTTP responses '
        'that disclose sensitive implementation details. Error responses included stack '
        'traces, internal exception messages, framework version information, database '
        'query fragments, internal file paths, or server configuration details. This '
        'information was returned to the client in response to crafted or malformed '
        'requests.'
    ),
    impact=(
        'Verbose error disclosure provides an attacker with detailed knowledge of the '
        'application technology stack, internal file system structure, database schema '
        'fragments, and software versions. This intelligence significantly aids '
        'reconnaissance and can be used to tailor targeted attacks against known '
        'vulnerabilities in the identified components.'
    ),
    remediation=(
        'Configure the application to display generic, user-friendly error messages in '
        'production. Ensure stack traces and internal exception details are written to '
        'server-side logs only, never returned to the client. Set framework debug modes '
        'to off in production environments. Implement a global exception handler that '
        'returns a consistent, non-informative error response. Review and test error '
        'handling for all application endpoints, including edge-case inputs.'
    ),
    references=(
        '- https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/08-Testing_for_Error_Handling/\n'
        '- CWE-209: https://cwe.mitre.org/data/definitions/209.html\n'
        '- https://owasp.org/Top10/A05_2021-Security_Misconfiguration/'
    ),
    tags=['owasp', 'cwe-209', 'a05:2021', 'information-disclosure', 'error-handling',
          'web_vapt', 'template:web_vapt', 'template:api_vapt'],
)

# ------------------------------------------------------------------
# 10. Hardcoded Secrets in AWS Lambda
# ------------------------------------------------------------------
add(
    title='Hardcoded Secrets in AWS Lambda Function',
    severity='High',
    cvss_score=7.7,
    cvss_vector='CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N',
    cwe='CWE-798 (Use of Hard-coded Credentials)',
    owasp='A02:2021',
    description=(
        'The review of the AWS Lambda function source code (or decompiled deployment '
        'package) identified that sensitive secrets were hardcoded directly in the '
        'function code or configuration. This included API keys, database credentials, '
        'JWT signing secrets, encryption keys, or third-party service tokens embedded '
        'as plaintext string literals. These secrets are accessible to any party with '
        'read access to the code repository, deployment artefacts, or Lambda function '
        'configuration.'
    ),
    impact=(
        'Hardcoded secrets exposed in Lambda code or repositories allow an attacker to '
        'authenticate to dependent services (databases, third-party APIs, cloud services) '
        'using the stolen credentials. Impact depends on the privilege level of the '
        'exposed secret and can range from data exfiltration and service abuse to full '
        'infrastructure compromise if administrative credentials are involved.'
    ),
    remediation=(
        'Remove all hardcoded secrets from Lambda function code immediately and rotate '
        'the exposed credentials. Store secrets in AWS Secrets Manager or AWS Systems '
        'Manager Parameter Store (SecureString). Retrieve secrets at runtime using the '
        'AWS SDK and IAM role-based access (no hardcoded AWS credentials). Use '
        'environment variables only for non-sensitive configuration; for sensitive '
        'values, prefer Secrets Manager integration. Scan the codebase and git history '
        'for leaked secrets using tools such as TruffleHog, GitLeaks, or AWS CodeGuru '
        'Secrets. Configure branch protection and pre-commit hooks to prevent future '
        'secret commits.'
    ),
    references=(
        '- https://docs.aws.amazon.com/secretsmanager/latest/userguide/intro.html\n'
        '- https://owasp.org/Top10/A02_2021-Cryptographic_Failures/\n'
        '- CWE-798: https://cwe.mitre.org/data/definitions/798.html\n'
        '- https://aws.amazon.com/blogs/security/how-to-use-aws-secrets-manager-securely-store-manage-credentials/'
    ),
    tags=['owasp', 'cwe-798', 'a02:2021', 'hardcoded-secrets', 'lambda', 'aws', 'cloud',
          'template:aws_cloud_vapt', 'template:source_code_review'],
    template_id=AWS,
)

db.commit()
total = db.query(FindingLibrary).count()
print(f'\nDone. Total library findings: {total}')
db.close()
