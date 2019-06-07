#!/bin/bash

declare query="process where name=\"${1}\" get"
declare psver="[math]::floor((New-TimeSpan -Start(Get-Date(Get-Process ${1//.exe}).StartTime) -End(Get-Date)).TotalSeconds)"

if test -z "${1}"; then
    printf "no imagename specified, cannot continue\n" 1>&2
    exit 1
fi

while sleep 5; do
    declare created=$(powershell.exe "${psver}" 2> /dev/null | tr -d '\r')
    declare parent=$(wmic.exe ${query} parentprocessid 2> /dev/null | egrep -m1 -o '^[0-9]+')

    # check that worked
    if test -z "${created}" -o -z "${parent}"; then
        printf "error running wmic, maybe no process yet\n"
        continue
    fi

    printf "%s has been running for %d seconds\n" ${1} ${created}

    # something has broken, kill parent.
    if ((created >= 30)); then
        taskkill.exe /f /pid ${parent}
        continue
    fi

    # force kill
    if ((created >= 10)); then
        taskkill.exe /f /im ${1}
        continue
    fi

    # gentle kill
    if ((created >= 5)); then
        taskkill.exe /im ${1}
    fi
done
