param (    
    # name of the output image
    [string]$mtitle = 'title1',
    [string]$mtext = 'text1'
)

[void] [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")

$objNotifyIcon = New-Object System.Windows.Forms.NotifyIcon

$objNotifyIcon.Icon = [System.Drawing.SystemIcons]::Information
$objNotifyIcon.BalloonTipIcon = "Warning" 
$objNotifyIcon.BalloonTipTitle = $mtitle 
$objNotifyIcon.BalloonTipText = $mtext
$objNotifyIcon.Visible = $True 
$objNotifyIcon.ShowBalloonTip(0)