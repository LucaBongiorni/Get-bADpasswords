# Get-bADpasswords

Compare password hashes of enabled Active Directory users with one or more lists of bad, weak or non-compliant passwords (e.g. hackers first guess in brute-force attack).
- Multiple word lists can be used.
- Can write log and CSV file output.
- Must be excuted with 'Domain Admin' or 'Domain Controller' permissions (or the like).

Requires PS Module "DSInternals" to be present on executing host. Please follow install instructions from there.
- Found here: https://www.powershellgallery.com/packages/DSInternals/
- More info:  https://www.dsinternals.com/en/

Note: this script does not modify input from word lists, like switching to upper/lower case etc. Each word in wordlist is taken as-is. Use other tools to generate word lists if needed.

Enjoy!
@JakobHeidelberg
