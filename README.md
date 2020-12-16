# security-json-import
Importing in the security.json

This tool attempts to recreate, as close as possible, the access data into an artifactory in lieu of a true access export.
https://jfrog.com/knowledge-base/how-to-import-access-data/

It requires:
artifactory.config.xml
security.json

These can be obtained via the support bundle. However, to achieve user to group assocation, you will need to manually get the assocation. I have provided two basic bash scripts that will get the association, but be beware that there are version requirements to use `getUsersFromGroups.sh` (6.13.0 and above). The other script is much slower, as it loops through every user, but should work on lower versions.

 
