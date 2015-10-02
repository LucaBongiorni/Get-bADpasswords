# Get-bADpasswords

Compare password hashes of active Active Directory users with list of bad or non-compliant passwords (e.g. hackers first guess in brute-force attack).
- Multiple wordlist can be used.
- Can write log and CSV file output.
- Must be excuted with 'Domain Admin' or 'Domain Controller' permissions (or the like).

Requires latest PowerShell version from Windows Management Framework 5.0 (Production Preview)

Requires PS Module "DSInternals" to be present on executing host. Please follow install instructions from there.
- Found here: https://www.powershellgallery.com/packages/DSInternals/
- More info:  https://www.dsinternals.com/en/

Note: this script does not modify input from wordlists, like switching to upper/lower case etc. Each word in wordlist is taken as-is. Use other tools to generate wordlists if needed.

Enjoy!
@JakobHeidelberg
