function newfunction($ShowTitle = $true) 
{
    if($ShowTitle)
    {
        Write-Host("----- Create new Contact -----")
    }

    try
    {
        
                
    }

    catch
    {
        Write-Host("Something went wrong when ...")
        
        $error = $_.Exception.Message
        log -Text "Something went wrong when ... See error message below:"
        log -Text "ERROR:: $error"
    }

    finally
    {
        if($ShowTitle)
        {
            Write-Host("`n")
        }
    } 
}