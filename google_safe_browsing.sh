#! /usr/bin/bash

api_url="https://safebrowsing.googleapis.com/v4/threatMatches:find?key="
key="AIzaSyAlMvN5CzQLENY43aeOB08Dwxefmjpo0v4"
command=" \"Content-Type: application/json\""
json="{ \"client\": { \"clientId\": \"LICENTA-Stoica-Gabriel\", \"clientVersion\": \"1.5.2\" }, \"threatInfo\": { \"threatTypes\": [\"MALWARE\", \"SOCIAL_ENGINEERING\"], \"platformTypes\": [\"WINDOWS\"], \"threatEntryTypes\": [\"URL\"], \"threatEntries\": ["
json_file="json_file.json"
json_response="json_response.json"
url_file=""

#DEFINE COLORS AREA
RED="tput setaf 1"
WHITE="tput setaf 7"
RED_BG="tput setab 1"
GREEN_BG="tput setab 2"
RESET="tput sgr 0"
BOLD="tput bold"

#DEFINE MESSAGES AREA
WARNING="$($RED_BG)ATENTIE!$($RESET) $($WHITE)"
NO_URL="$($GREEN_BG)FISIERUL NU CONTINE URL-URI MALITIOASE!$($RESET) $($WHITE)"

function _api_create_json(){
    url_file=$1
    local file_lines=$(wc -l $url_file | awk '{print $1}')
    #file_line=$((file_lines-1))
    
    local counter=1
    local url=""
    local json_url=""
    while read line;
    do
        
        if [ $counter -lt $file_lines ]
        then
            url=$(echo $line | awk '{print $3}')
            json_url="{\"url\": \"$url\"},"
            json=${json}$json_url
        else
            url=$(echo $line | awk '{print $3}')
            json_url="{\"url\": \"$url\"}"
            json=${json}$json_url
        fi
        counter=$((counter+1))
    done < $url_file
    
    json=${json}"]}}"
    
    if [ ! -f $json_file ]
    then
        touch $json_file
    else
        > $json_file
    fi
    
    echo -e $json | jq '.' >> $json_file
    
    _api_make_post
}

function _api_make_post(){
    api_url=${api_url}$key
    command="curl -s -X POST -H"${command}" -d @"$json_file" "$api_url
    
    #echo $command
    local result=$(eval $command)
    if [ "$result" == "{}" ]
    then
        echo -e "*******************$NO_URL*******************"
        echo -e "Scanarea fisierului impotriva URL-urilor malitioase a fost finalizata!"
    else
        if [ ! -f $json_response ]
        then
            echo -e $result | jq '.' >> $json_response
        else
            > $json_response
            echo -e $result | jq '.' >> $json_response
        fi
        
        local threatType_list=$(jq '.matches | .[].threatType' $json_response)
        local url_list=$(jq '.matches | .[].threat.url' $json_response)
        local counter=0
        
        #local line_number=0
        #cat $url_file
        
        local line=0
        for item in $threatType_list
        do
            url_list[counter]=$(echo ${url_list[counter]} | sed 's/\"//g')
            line=$(grep ${url_list[counter]} $url_file | awk '{print $1}')
            echo -e "******************* $WARNING*******************"
            echo "URL potential malitios identificat pe linia ${line}! Tip atac: $item; URL: ${url_list[counter]}"
            counter=$((counter+1))
        done
    fi
    
}

function test_function(){
    local json_file=$1
    command=$command" -d @"$1" "$url$key
    echo $command
}
