#!/bin/bash

art=http://localhost:8081/artifactory
user=loreny
password=password
file=groupsWithUsers.json

groups=($(curl -u $user:$password $art/api/security/groups | jq -r '.[] | .name'))
echo "{\"groups\":[" > $file
for i in ${groups[@]}; do
    # this requires Artifactory 6.13 and above
    echo "$(curl -u $user:$password "$art/api/security/groups/$i?includeUsers=true")," >> $file
done
# sometimes this command doesn't exist so you'll want to manually remove the last comma
truncate -s-1 $file
echo "]}" >> $file
