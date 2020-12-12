#!/bin/bash

art=http://localhost:8081/artifactory
user=admin
pass=password
file=userList.json

users=($(curl $art/api/security/users -u $user:$pass | jq -r '.[] | .name'))
echo "{ \"users\": [" > $file
for i in ${users[@]}; do
    echo "$(curl $art/api/security/users/$i -u $user:$pass)," >> $file
done
# sometimes this command doesn't exist so you'll want to manually remove the last comma
truncate -s-1 $file
echo "]}" >> $file
