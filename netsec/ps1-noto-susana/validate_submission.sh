#!/bin/bash

##
## Tien Vo-Huu (tienvh@ccs.neu.edu)
##
## This script validates a submission by checking its structure

FAIL=""

usage() {
    echo ""
    echo "Usage: `basename $0` <SUBMISSION_DIR>"
    echo ""
    exit 1
}

warning_wrong_dirname_format() {
    echo "Submission directory name is not in the right format."
    echo "It should be in this format: <problem_set>-<lastname>-<firstname>"
    echo ""
    echo "Example: ps1-Baby-Shark"
    echo ""
    FAIL=true
}

###################################
########## Porblem Set 1 ##########
###################################

print_ps1_structure() {
    cat >&2 << _PS1

    -----------------------------------------------------
    |   Structure of Problem Set 1:                     |
    |   <ps1-lastname-firstname>/                       |
    |                                                   |
    |   <ps1-lastname-firstname>/q1/report.pdf          |
    |   <ps1-lastname-firstname>/q1/proof-log/*.*       |
    |                                                   |
    |   <ps1-lastname-firstname>/q2/src/chat_server.py   |
    |   <ps1-lastname-firstname>/q2/src/chat_client.py   |
    |   <ps1-lastname-firstname>/q2/src/README.txt      |
    |   <ps1-lastname-firstname>/q2/src/*.*             |
    -----------------------------------------------------
_PS1
}

check_ps1() {
    local subdir=$1

    require=""
    require="$require q1/report.pdf"
    require="$require q1/proof-log/"
    require="$require q2/src/chat_server.py"
    require="$require q2/src/chat_client.py"
    require="$require q2/src/README.txt"

    ls -lR $subdir

    for r in ${require[*]}; do
        if [ -f "$subdir/$r" ] || [ -d "$subdir/$r" ]; then
            continue
        else
            printf "%s -- NOT Found\n" "$subdir/$r"
            FAIL=true
        fi
    done
}


###################################
########## Porblem Set 2 ##########
###################################

print_ps2_structure() {
    cat >&2 << _PS2

    -----------------------------------------------------
    |   Structure of Problem Set 2:                     |
    |   <ps2-lastname-firstname>/                       |
    |   <ps2-lastname-firstname>/report.pdf             |
    |   <ps2-lastname-firstname>/src/fcrypt.py          |
    |   <ps2-lastname-firstname>/src/README             |
    |   <ps2-lastname-firstname>/src/*.*                |
    -----------------------------------------------------
_PS2
}

check_ps2() {
    local subdir=$1

    require=""
    require="$require report.pdf"
    require="$require src/fcrypt.py"
    require="$require src/README.txt"

    ls -lR $subdir

    for r in ${require[*]}; do
        if [ -f "$subdir/$r" ] || [ -d "$subdir/$r" ]; then
            continue
        else
            printf "%s -- NOT Found\n" "$subdir/$r"
            FAIL=true
        fi
    done
}


##### MAIN #####
SUBMISSION_DIR="${1%\/}"
if [ -z "$SUBMISSION_DIR" ]; then
    usage
fi

if [ ! -d "$SUBMISSION_DIR" ]; then
    echo "Error: $SUBMISSION_DIR not existed."
    usage
fi

echo ""
echo "####### VALIDATE SUBMISSION #######"

echo "-- Checking Directory Name"

sbname=`basename $SUBMISSION_DIR`
problem_set=`echo $sbname | grep -oE "^ps[1-4]"`

if [ -z "$problem_set" ]; then
    echo "Could not determine Problem Set"
    warning_wrong_dirname_format
fi

sbname=${sbname#$problem_set-}
if [ -z "$FAIL" ]; then
    lastname=`echo $sbname | grep -oE "^[a-zA-Z0-9]+"`
    if [ -z "$lastname" ]; then
        echo "Could not determine Last Name"
        warning_wrong_dirname_format
    fi
fi

sbname=${sbname#$lastname-}
if [ -z "$FAIL" ]; then
    firstname=`echo $sbname | grep -oE "^[a-zA-Z0-9]+"`
    if [ -z "$firstname" ]; then
        echo "Could not determine First Name"
        warning_wrong_dirname_format
    fi
fi


if [ -z "$FAIL" ]; then
    echo "Problem set: $problem_set"
    echo "Firstname: $firstname"
    echo "Lastname: $lastname"
    echo ""
fi

case "$problem_set" in
    ps1)
        echo "-- Checking Problem Set 1 structure"
        check_ps1 $SUBMISSION_DIR
        ;;
    ps2)
        echo "-- Checking Problem Set 2 structure"
        check_ps2 $SUBMISSION_DIR
        ;;
esac

if [ -z "$FAIL" ]; then
    echo ""
    echo "##### VALIDATION SUCCESSFUL #####"
else
    echo ""
    echo "##### VALIDATION FAILED #####"
    if [ "$problem_set" = "ps1" ]; then print_ps1_structure; fi
    if [ "$problem_set" = "ps2" ]; then print_ps2_structure; fi
fi



