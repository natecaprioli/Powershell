$getpid = get-process explorer -IncludeUsername | where-object {$_.username -like 'CONTOSO\UserN*'} | select-object -ExpandProperty ID
Foreach ($id in $getpid) {taskkill /pid $id /f}
