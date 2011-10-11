require 'albacore'
require 'version_bumper'

def env_buildversion
  bumper_version.to_s
end

desc "Build project"
task :default => ['bump:build', 'albacore:assemblyinfo', 'albacore:msbuild', 'albacore:mspec']
     
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
  	mspec.assemblies "../build/working/JsonWebTokenTests.dll"
  end

  all_assemblies_map = {
    'jwt4net_asminfo' => {:folder => 'JsonWebToken'}
  }
	
	all_assemblies_map.each do |assembly_name, values|
	  puts "Defining task :#{assembly_name}"
	  folder = values[:folder]
	  vFile = "#{folder}\\VERSION"
	  puts "Using version file #{vFile}"
	  bumper_file vFile
	  assemblyinfo assembly_name.to_sym do |asm|
	    asm.output_file = "#{folder}\\Properties\\assemblyinfo.cs"
	    asm.version = bumper_version.to_s
	  end
	end
	
	desc 'Update assembly info'
	task :assemblyinfo => all_assemblies_map.keys
end