#! /usr/bin/bash
set -e

#SOURCES
source google_safe_browsing.sh

#DEFINE VARIABLES
script_pid=$$
fingerprints_uploads_dir=$PWD"/fingerprints_uploads" #directory where SHA-256 hashes of files in uploads/ directory are stored
logo_file="logo.txt"
to_be_scanned=0
scanned=0

#VARIABLES FOR INTEGRITY OPTION
config_dir_backup=""
config_dir=""

#VARIABLES FOR UPLOAD OPTION
uploads_dir="" #absolute path to uploads directory
integrity_file_location=$PWD"/"
integrity_file="integrity_file.txt"

#VARIABLES FOR LOGGING
raports_directory=$PWD"/raports"
log_file="log_file.txt" #log file where incidents are journalized
json_file="incidents.json"
url_file="url_file.txt"
json_content="["

#DEFINE COLORS AREA
RED="tput setaf 1"
WHITE="tput setaf 7"
RED_BG="tput setab 1"
GREEN_BG="tput setab 2"
RESET="tput sgr 0"
BOLD="tput bold"

#DEFINE MESSAGES AREA
WARNING="$($RED_BG)ATENTIE!$($RESET) $($WHITE)"
CONFIRM="$($GREEN_BG)INTEGRITATE CONFIRMATA!$($RESET) $($WHITE)"
NO_XSS="$($GREEN_BG)NU S-A DETECTAT CONTINUT XSS MALITIOS!$($RESET) $($WHITE)"

############################################################
#Functie care compara hash-urile fisierelor actuale, cu    #
#cele initiale, stocate in fisierul "integrity_file.txt"  #
#Utilizata in cadrul optiunii -u, -uploads                 #
############################################################
function _scan_for_changes(){
    
    local FILE=$1
    
    local file_name="${FILE##$uploads_dir"/"}"
    local file_hash=$(sha256sum $FILE | awk '{print $1}')
    local trusted_hash=$(grep $file_name $integrity_file | awk '{print $3}' | head -1)
    
    # echo "Trusted hash of " $file_name " " $trusted_hash
    # echo "Actual hash of " $file_name " " $file_hash
    
    if [ -z $trusted_hash ]  #hash not found => new file
    then
        echo -e "new_file" $file_name
    elif [ "$file_hash" != "$trusted_hash" ] #hash not equal with trusted one => file modifications
    then
        echo -e "exit_signal"
    fi
}

###########################################################
#Functie care calculeaza hash-ul fisierelor din folderul  #
#de back-up dat ca parametru, folosing algoritmul SHA-256 #
###########################################################
function _compute_backup_integrity(){
    for FILE in "$1/"*
    do
        if [ -f "$FILE" ]
        then
            local file_hash=$(sha256sum $FILE | awk '{ print $1 }')
            local file_name="${FILE##$config_dir_backup"/"}"
            echo -e $file_name" --> "$file_hash >> $integrity_file
        elif [ -d "$FILE" ]
        then
            _compute_backup_integrity $FILE
        fi
    done
}

function _scan_uploads(){
    if [ ! -f "$integrity_file" ]
    then
        touch $integrity_file
    else
        > $integrity_file
    fi
    
    if [ ! -f "$log_file" ]
    then
        touch $log_file
    fi
    
    check_result=0
    _compute_backup_integrity $1
    
    while [ $check_result -eq 0 ]
    do
        for FILE in "$uploads_dir/"*
        do
            if [ -f "$FILE" ]
            then
                file_integrity=$(_scan_for_changes $FILE)
                current_time=$(date +"%Y-%m-%d %T")
                if [ "$file_integrity" == "exit_signal" ]
                then
                    echo "WARNING: FILE MODIFICATIONS OCCURED! CHECK LOG FILE!"
                    echo -e "[ "$current_time" ] WARNING: FILE MODIFICATIONS in "$FILE": "${file_integrity//"new_file"/} >> $log_file
                    exit 1
                    check_result=1
                elif echo $file_integrity | grep -q "new_file"
                then
                    echo "WARNING: NEW FILE UPLOADED! CHECK LOG FILE!"
                    echo -e "[ "$current_time" ] WARNING: NEW FILE UPLOADED in "$uploads_dir": "${file_integrity//"new_file"/} >> $log_file
                    exit 1
                    check_result=1
                else
                    echo "scanning.."
                    echo -e "[ "$current_time" ] NO PROBLEMES FOUND" >> $log_file
                    check_result=0
                fi
            fi
        done
        sleep 1
    done
    
}

function _scan_integrity(){
    if [ ! -f "$integrity_file" ]
    then
        touch $integrity_file
    else
        > $integrity_file
    fi
    
    if [ ! -d $raports_directory ]
    then
        mkdir $raports_directory
    else
        rm -Rf $raports_directory/*
    fi
    
    echo -e "Se calculeaza hash-urile fisierelor din directorul de backup..."
    _compute_backup_integrity $config_dir_backup
    _check_integrity $config_dir
}

function _create_url_file(){
    local line=$1
    local line_number=$2
    
    #echo $line
    local check_for_url=$(echo $line | egrep -o "(https?|ftp|file)://[-A-Za-z0-9\+&@#/%?=~_|\!:,.;]*[-A-Za-z0-9\+&@#/%=~_|]")
    
    #send to Google Safe Browsing API
    #to check if any URL from file
    #is not on Green List
    if [[ ! -z "$check_for_url" ]]
    then
        #echo "Linia $line_number, cu URL-ul: $check_for_url"
        for url in $check_for_url
        do
            #echo $url
            echo -e $line_number" --> " $url >> $url_file
        done
    fi
}

###########################################################
#Functie care scaneaza un fisier impotriva atacurilor de  #
#tip XSS, Javascript injection si URL-uri malitioase      #
###########################################################
function _detect(){
    local FILE=$1
    local blacklist=("xss" "XSS" "onmouseover" "alert" "onerror" "document" "cookie" "document.cookie" "JaVaScRiPt" "iframe")
    local line_number=1
    if [ ! -f $url_file ]
    then
        touch $url_file
    else
        > $url_file
    fi
    
    echo -e "Scanarea fisierului impotriva atacurilor de tip XSS a inceput..."
    sleep 2
    
    local found=0
    local total_warnings=0
    while read line; do
        #sleep 1
        _create_url_file "$line" $line_number
        
        #loop through every line from file
        #and check if any word is
        #on XSS-attack-words list
        for word in $line
        do
            found=0
            for item in ${blacklist[@]}
            do
                
                if [[ "$word" =~ $item ]] && [ $found -eq 0 ]
                then
                    echo -e "******************* $WARNING*******************"
                    echo "A fost detectat continut potential malitios pe linia $line_number: cod JAVASCRIPT, potential atac de tip XSS"
                    echo -e $line"\n"
                    found=1
                    total_warnings=$((total_warnings+1))
                fi
            done
        done
        line_number=$((line_number+1))
    done < $FILE
    
    if [ $total_warnings -eq 0 ]
    then
        echo -e "*******************$NO_XSS*******************"
        echo -e "Scanarea fisierului impotriva atacurilor de tip XSS a fost finalizata!"
    else
        echo -e "Scanarea fisierului impotriva atacurilor de tip XSS a fost finalizata!"
    fi
    
    echo -e "\nScanning file against malicious URLs..."
    _api_create_json "$url_file"
    
}

############################################################
#Functie care compara hash-urile fisierelor actuale, cu    #
#cele initiale, stoacate in fisierul "integrity_file.txt"  #
#Utilizata in cadrul optiunii -i, -integrity               #
############################################################
function _compare_fingerprints(){
    scanned=$((scanned+1))
    
    local FILE=$1
    
    local file_name="${FILE##$config_dir"/"}"
    local file_hash=$(sha256sum $FILE | awk '{print $1}')
    local trusted_hash=$(grep $file_name $integrity_file | awk '{print $3}' | head -1)
    
    echo "Trusted hash of " $file_name " " $trusted_hash
    echo "Actual hash of " $file_name " " $file_hash
    
    current_time=$(date +"%Y-%m-%d %T")
    if [ -z $trusted_hash ]  #hash not found => new file
    then
        local last_modification=$(date -r $FILE)
        echo -e "$($BOLD)$WARNING Fisier nou adaugat: "$file_name
        echo -e "Ultima modificare asupra fisierului a fost la data "$last_modification
        echo -e "[ "$current_time" ] WARNING: FILE MODIFICATIONS in "$file_name". CHECK RAPORT FILE: "$raports_directory/$file_name"" >> $log_file
        _write_to_json_content $PWD $file_name "integrity" "Fisier nou" $current_time

    elif [ "$file_hash" != "$trusted_hash" ] #hash not equal with trusted one => file modifications
    then
        
        echo -e "$($BOLD)$WARNING Fisierul "$file_name" a fost modificat!"
        echo -e "Verificati fisierul raport_"$file_name" pentru a investiga incidentul!"
        echo -e "[ "$current_time" ] WARNING: FILE MODIFICATIONS in "$file_name". CHECK RAPORT FILE: "$raports_directory/"raport_"$file_name".txt" >> $log_file
        _write_to_json_content $PWD $file_name "integrity" "Integritate" $current_time

        _generate_raport $FILE $file_name
    else
        echo -e "$CONFIRM Integritatea fisierului "$file_name" confirmata!"
        echo -e "[ "$current_time" ] CONFIRM: Integritatea fisierului "$file_name" confirmata!" >> $log_file
    fi
}

function _generate_raport(){
    #$1 compromised FILE
    #$2 backup FILE
    local FILE=$1
    local file_name=$2
    local file_name_basename=$(basename $file_name)
    
    local last_modification=$(date -r $FILE)
    local modifications=$(diff $config_dir_backup$file_name $FILE)
    local raport_location=$(echo $raports_directory/"raport_"$file_name_basename".log")
    
    touch $raport_location
    echo -e "Fisierul a fost modificat la data "$last_modification >> $raport_location
    echo -e "Urmatoarele modificari au avut loc:" >> $raport_location
    echo $modifications >> $raport_location
    #local generate_raport=$(sdiff $config_dir_backup"/"$file_name $FILE >> $raport_location)
}

function _check_integrity(){
    for ENTRY in "$1/"*
    do
        if [ -f $ENTRY ]
        then
            _compare_fingerprints $ENTRY
        elif [ -d $ENTRY ]
        then
            _check_integrity $ENTRY
        fi
    done
    
    
}

function _check_for_modifications(){
    
    local directory=$1
    local mtime_value=$2
    local check_directory_name=$(echo "${directory: -1}")
    
    if [ $check_directory_name != "/" ]
    then
        directory+="/"
    fi
    directory+="*"
    
    if [ ! -z "$mtime_value" ]
    then
        find $directory -mtime $mtime_value
    else
        find $directory -mtime -1
    fi
    
}

function _write_to_json_file(){
    
    json_content=${json_content::-1}
    json_content=${json_content}"]"
    
    if [ ! -f $json_file ]
    then
        touch $json_file
    else
        > $json_file
    fi
    
    echo -e $json_content | jq '.' >> $json_file
    
}
#parametrii
#$1 - platforma, $2 - fisier, $3 - mod, $4 - tip amenintare, $5 - data
function _write_to_json_content(){

    json_content=${json_content}"{\"platforma\":\""$1"\",";
    json_content=${json_content}"\"fisier\":\""$2"\",";
    json_content=${json_content}"\"mod\":\""$3"\",";
    json_content=${json_content}"\"tip_amenintare\":\""$4"\",";
    json_content=${json_content}"\"data\":\""$5"\"},";

}

function _help(){
    
    usage="\nshield scan – Scrip creat pentru detectia fisierelor noi incarcate in cadrul unui director sensibil \nsi detectarea potentialelor modificari asupra integritatii fisierelor, precum si a atacurilor de tip RCE, XSS si URL phishing \n(c) Stoica Gabriel-Marius <marius_gabriel1998@yahoo.com> \n \nMod de utilizare: ./$(basename "$0") [-h] [-u /path/to/uploads/] [-i /path/to/backup/ path/to/actual/] [-d /path/to/file.txt]  \n \navand semnificatia: \n \t -h, -help \n \t\tAjutor, arata modul de utilizare \n \t -u, -uploads [/path/to/directory]  \n \t\tScanarea unui director pentru detectia incarcarii noilor fisiere: \n \t\tasteapta ca parametrul calea catre un director \n \t -i, -integrity [/path/to/backup/ path/to/actual_dir/] \n \t\tCalculeaza hash-ul fisierelor din folderul de backup si il compara \n\t\tcu hash-ul fisierelor din folderul scanat, pentru a identifica potentiale \n\t\tmodificari malitioase, precum: atacuri de tip XSS, inserare de cod Javascript, URL-uri de tip phishing \n \t -d, -detect [/path/to/file.txt] \n \t\tEfectueaza scanarea completa a unui \n \t\tfisier dat ca parametru, impotriva atacurilor de tip XSS, Javascript code, URL-uri de tip phishing "
    
    cat $logo_file
    echo -e $usage
}


function main(){
    if [ $# -eq 0 ]
    then
        _help
    elif [ $1 == "--help" ] || [ $1 == "-h" ]
    then
        _help
    elif [ $1 == "-uploads" ] || [ $1 == "-u" ]
    then
        if [ -d $2 ]
        then
            cat $logo_file
            uploads_dir=$2
            _scan_uploads $uploads_dir
        else
            _help
        fi
    elif [ $1 == "-integrity" ] || [ $1 == "-i" ]
    then
        if [ -d $2 ] && [ -d $3 ]
        then
            to_be_scanned=$(find $config_dir -type f| wc -l)
            cat $logo_file
            config_dir_backup=$2
            config_dir=$3
            _scan_integrity
            _write_to_json_file
            
            echo -e "Scanare completa! Au fost scanate $scanned/$to_be_scanned fisiere!"
            echo -e "Folderul de back-up: $config_dir_backup contine $(find $config_dir_backup -type f | wc -l) fisiere"
            echo -e "Folderul scanat: $config_dir contine $(find $config_dir -type f | wc -l) fisiere"
            
        else
            _help
        fi
    elif [ $1 == "-detect" ] || [ $1 == "-d" ]
    then
        if [ ! -f $2 ]
        then
            echo -e "Nu s-a putut realiza deschiderea fisierului $2!"
        else
            cat $logo_file
            _detect $PWD"/"$2
        fi
    elif [ $1 == "-check_mod" ] || [ $1 == "-cm" ]
    then
        if [[ (! -d $2) || ( -z $2 ) ]]
        then
            _help
        else
            if [ -z $3 ]
            then
                _check_for_modifications $2
            elif [ $3 == "-mt" ]
            then
                if [[ "$4"  =~ ^([0-9]+) ]]
                then
                    _check_for_modifications $2 $4
                else
                    _help
                fi
            else
                _help
            fi
        fi
    else
        _help
    fi
}

main "$@"
