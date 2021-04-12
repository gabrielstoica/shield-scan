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
json_content=""
verbose_mode=0

#DEFINE COLORS AREA
RED="tput setaf 1"
YELLOW="tput setaf 3"
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
    echo $1
    _compute_backup_integrity $1
    uploads_dir=$1
    
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
                    if [ $verbose_mode -eq 1 ]
                    then
                        echo "scanning.."
                    fi
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
    
    local check_for_url=$(echo $line | egrep -o "(https?|ftp|file)://[-A-Za-z0-9\+&@#/%?=~_|\!:,.;]*[-A-Za-z0-9\+&@#/%=~_|]")
    
    #send to Google Safe Browsing API
    #to check if any URL from file
    #is not on Green List
    if [[ ! -z "$check_for_url" ]]
    then
        for url in $check_for_url
        do
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
    
    if [ $verbose_mode -eq 1 ]
    then
        echo "Trusted hash of " $file_name " " $trusted_hash
        echo "Actual hash of " $file_name " " $file_hash
    fi
    
    current_time=$(date +"%Y-%m-%d %T")
    if [ -z $trusted_hash ]  #hash not found => new file
    then
        local last_modification=$(date -r $FILE)
        echo -e "$($BOLD)$WARNING Fisier nou adaugat: "$file_name
        echo -e "Ultima modificare asupra fisierului a fost la data "$last_modification
        echo -e "[ "$current_time" ] WARNING: FILE MODIFICATIONS in "$file_name". CHECK RAPORT FILE: "$raports_directory/$file_name"" >> $log_file
        _write_to_json_content $config_dir $file_name "integrity" "Fisier nou" $current_time
        
    elif [ "$file_hash" != "$trusted_hash" ] #hash not equal with trusted one => file modifications
    then
        
        echo -e "$($BOLD)$WARNING Fisierul "$file_name" a fost modificat!"
        echo -e "Verificati fisierul raport_"$file_name" pentru a investiga incidentul!"
        echo -e "[ "$current_time" ] WARNING: FILE MODIFICATIONS in "$file_name". CHECK RAPORT FILE: "$raports_directory/"raport_"$file_name".txt" >> $log_file
        _write_to_json_content $config_dir $file_name "integrity" "Integritate" $current_time
        
        _generate_raport $FILE $file_name
    else
        if [ $verbose_mode -eq 1 ]
        then
            echo -e "$CONFIRM Integritatea fisierului "$file_name" confirmata!"
        fi
        echo -e "[ "$current_time" ] CONFIRM: Integritatea fisierului "$file_name" confirmata!" >> $log_file
    fi
}

function _generate_raport(){
    
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
    local current_date=$(date +"%Y-%m-%d")
    
    if [ $check_directory_name != "/" ]
    then
        directory+="/"
    fi
    directory+="*"
    
    if [ ! -z "$mtime_value" ]
    then
        mtime_value=$2
    else
        mtime_value=1
    fi
    
    local files_modified=$(find $directory -mtime -$mtime_value)
    local files_number=$(find $directory -mtime -$mtime_value | wc -l)
    local total_files=$(ls $directory | wc -l)
    local past_date=$(date -d "$mtime_value day ago" +"%Y-%m-%d")
    
    if [ -z "$files_modified" ]
    then
        echo -e "Au fost identificate 0 fisiere modificate in perioada "$past_date" -- "$current_date
    else
        echo -e "Director scanat:" $1
        echo -e "Fisiere scanate:" $total_files
        echo -e "Fisiere modificate:" $files_number
        echo -e "Au fost identificate urmatoarele fisiere modificate in perioada "$past_date" -> "$current_date"\n"
        echo $files_modified | tr " " "\n"
        
    fi
    
}

function _write_to_json_file(){
    
    json_content=${json_content::-1}
    
    local old_json_content=""
    if [ ! -f $json_file ]
    then
        touch $json_file
        json_content="["${json_content}"]"
    else
        old_json_content=$(cat $json_file)
        old_json_content=${old_json_content::-1}
        old_json_content=${old_json_content}","
        old_json_content=${old_json_content}${json_content}"]"
        > $json_file
        json_content=${old_json_content}
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
    
    usage="\n\tUtilitar conceput pentru detectia modificarilor si analiza integritatii fisierelor \n\t\tdin cadrul unui director, pentru a putea anticipa comportamente\n\t anormale si reactiona in cazul atacurilor de tip RCE, XSS si URL phishing \n\n\t\t(c) Stoica Gabriel-Marius <marius_gabriel1998@yahoo.com> \n \nMod de utilizare: ./$(basename "$0") [-h] OPTIONS {target} \n \navand semnificatia: \n \t -h, --help \n \t\tAjutor, arata modul de utilizare \n\n \t -u, --uploads [/path/to/directory]  \n \t\tScanaza un director tinta pentru detectia incarcarii noilor fisiere: \n \t\tasteapta ca parametrul calea catre un director \n\n \t -i, --integrity [/path/to/backup/ path/to/actual_dir/] \n \t\tCalculeaza hash-ul fisierelor din folderul de backup si il compara \n\t\tcu hash-ul fisierelor din folderul scanat, pentru a identifica potentiale \n\t\tmodificari\n\n \t -d, --detect [/path/to/file.txt] \n \t\tEfectueaza scanarea completa a unui fisier dat ca parametru,\n \t\timpotriva atacurilor de tip XSS, Javascript code,\n\t\tURL-uri de tip phishing\n \n \t -cm, --check-mod [/path/to/directory/] [-mt N] \n \t\tEfectueaza scanarea completa a unui director dat ca parametru,\n \t\tsi identifica fisierele care au suferit modificari\n\t\tin ultimele N zile\n\n\t -v, --verbose \n\t\tActiveaza modul afisare explicita, determinand utilitarul sa afiseze \n\t\tinformatii intermediare intre operatiile efectuate"
    $YELLOW
    cat $logo_file
    $RESET
    echo -e $usage
}


function main(){
    
    local help_mode=0
    local uploads_mode=0
    local integrity_mode=0
    local detect_mode=0
    local check_mode=0
    local undefined_mode=0
    
    local directory=""
    local backup_directory=""
    local file=""
    local mtime=1
    
    if [ $# -eq 0 ]
    then
        _help
    else
        for (( arg=1; arg<=$#; arg++ ))
        do
            case ${!arg} in
                -h|--help)
                    help_mode=1;
                ;;
                -u|--uploads)
                    uploads_mode=1;
                    shift;
                    directory=${!arg};
                ;;
                -v|--verbose)
                    verbose_mode=1;
                ;;
                -i|--integrity)
                    integrity_mode=1;
                    shift;
                    backup_directory=${!arg};
                    shift;
                    directory=${!arg};
                ;;
                -d|--detect)
                    detect_mode=1;
                    shift;
                    file=${!arg};
                ;;
                -cm|--check-mod)
                    check_mode=1;
                    shift;
                    directory=${!arg};
                ;;
                -mt|--mtime)
                    shift;
                    mtime=${!arg};
                ;;
                *)
                    undefined_mode=1;
                ;;
            esac
        done
        
        
        if [ $undefined_mode -eq 1 ]
        then
            echo -e "Scanare esuata! Parametru invalid. Consultati ./shield-Scan.sh --help"
        elif [ $help_mode -eq 1 ]
        then
            _help
        elif [ $uploads_mode -eq 1 ]
        then
            if [ -d $directory ]
            then
                echo -e "Scanarea continua a inceput! Utilitarul scaneaza directorul: "$directory
                _scan_uploads $directory
            else
                _help
            fi
        elif [ $integrity_mode -eq 1 ]
        then
            if [ -d $directory ] && [ -d $backup_directory ]
            then
                config_dir_backup=$backup_directory
                config_dir=$directory
                
                to_be_scanned=$(find $config_dir -type f | wc -l)
                echo -e "\n\t\t Procesul de scanare a inceput! \n"
                
                _scan_integrity
                _write_to_json_file
                
                echo -e "##################################################################"
                echo -e "Scanare completa! Au fost scanate $scanned / $to_be_scanned fisiere!"
                echo -e "Folderul de back-up: $config_dir_backup contine $(find $config_dir_backup -type f | wc -l) fisiere"
                echo -e "Folderul scanat: $config_dir contine $(find $config_dir -type f | wc -l) fisiere"
                
            else
                _help
            fi
        elif [ $detect_mode -eq 1 ]
        then
            if [ ! -f $file ]
            then
                echo -e "Nu s-a putut realiza deschiderea fisierului $file!"
            else
                cat $logo_file
                _detect $PWD"/"$file
            fi
        elif [ $check_mode -eq 1 ]
        then
            if [[ ( ! -d $directory ) || ( -z $directory ) ]]
            then
                _help
            else
                if [[ "$mtime"  =~ ^([0-9]+) ]]
                then
                    _check_for_modifications $2 $4
                else
                    _help
                fi
            fi
        else
            _help
        fi
        
    fi
}

main "$@"
