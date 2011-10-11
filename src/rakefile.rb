require 'albacore'
require 'version_bumper'

desc "Build project"
task :default => ['bump:build', 'albacore:assemblyinfo', 'albacore:msbuild', 'albacore:mspec', 'merge_jwt4net', 'merge_keytool']
     
desc "Merge outputs"
exec :merge_jwt4net do |cmd|
    cmd.command = '../build/ilmerge/ilmerge.exe'
    cmd.parameters ='/out:..\build\jwt4net.dll /t:library ..\build\working\jwt4net.dll ..\build\working\litjson.dll ..\build\working\microsoft.practices.servicelocation.dll ..\build\working\security.cryptography.dll ..\build\working\penge.dll'
    puts 'merging jwt4net to build\jwt4net.dll'
end     

desc "Merge outputs"
exec :merge_keytool do |cmd|
    cmd.command = '../build/ilmerge/ilmerge.exe'
    cmd.parameters ='/out:..\build\keytool.exe /t:executable ..\build\working\keytool.exe ..\build\working\jwt4net.dll ..\build\working\litjson.dll ..\build\working\microsoft.practices.servicelocation.dll ..\build\working\security.cryptography.dll ..\build\working\penge.dll'
    puts 'merging keytool to build\keytool.exe'
end     
     
 namespace :albacore do
    		
  desc "Build solution with MSBuild"
  msbuild :msbuild do |msb|
	msb.properties :configuration => :Debug
      msb.targets [:Clean, :Build]
      msb.solution = "Jwt4Net.sln"
  end

  desc "MSpec Test Runner Example"
  mspec do |mspec|
  	mspec.command = "../build/MSpec/mspec.exe"
  	mspec.assemblies ["../build/working/JsonWebTokenTests.dll", "../build/working/Cng2Pem.Tests.dll"]
  end

  all_assemblies_map = {
    'jwt4net_asminfo' => {:folder => 'JsonWebToken'},
    'keytool_asminfo' => {:folder => 'KeyTool'},
    'penge_asminfo' => {:folder => 'Cng2Pem'},
  }
	
	all_assemblies_map.each do |assembly_name, values|
	  puts "Defining task :#{assembly_name}"
	  folder = values[:folder]
	  assemblyinfo assembly_name.to_sym do |asm|
	    asm.output_file = "#{folder}\\Properties\\assemblyinfo.cs"
	    asm.version = bumper_version.to_s
	  end
	end
	
	desc 'Update assembly info'
	task :assemblyinfo => all_assemblies_map.keys
end