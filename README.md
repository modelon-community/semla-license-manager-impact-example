# License Manager Impact Example

This project is an example of a [SEMLA](https://github.com/modelica/Encryption-and-Licensing) License Manager for Modelon Impact

## How to setup for use online on https://impact.modelon.cloud
> [!WARNING]  
> When building online the encrypted library will be only compatible 
> with the *latest* execution environment and may fail to load in default (stable)
> and older versions due to system library differences.

Login into your Modelon Impact cloud account, navigate to [Project explorer app](https://impact.modelon.cloud/user-redirect/impact/customizations/workspace_management/index.html?view=projects) and checkout 
this repository.

Use context menu to open VSCode in browser for this checkout. With default location the VSCode URL will be: 
https://impact.modelon.cloud/user-redirect/vscode/?folder=/home/jovyan/impact/local_projects/Semla-license-manager-impact-example 

Open terminal (Ctrl-Shift-C) and run the setup script: `./setup.sh`. The script will:
  - Git clone SEMLA repository to `../SEMLA` 
  - Download dependencies from a release in this repository
  - Generate keys for testing in `../openssl_keys`
  - Creates a Python virtual environment under build/venv and installs cmake into it.

Activate the build environment if you need to use cmake from command line with `source build/venv/activate`.

## How to setup locally
We recommend using VS Code with a devcontainer. There is a devcontainer set up in this repo, which enables an easy and reproducible setup.
The devcontainer mounts in the parent directory of this directory, so that both this directory, and the `../SEMLA` directory are available in the container.
Pre-requisites are that VS Code and Docker (and WSL if running on Windows) are installed.
For more information on how to use the devcontainer, search for "devcontainer" in:
- [SEMLA: Building instructions](https://github.com/modelica/Encryption-and-Licensing/blob/master/src)

- Run `setup.sh`. This will:
  - Git clone SEMLA to `../SEMLA` 
  - Download dependencies from a release in this repository
  - Generate keys for testing in `../openssl_keys`

The build system assumes that the directories are laid out like this:
```
openssl_keys/
SEMLA/
semla-license-manager-impact-example/    # (this directory)
```

## Create a license file
The example uses a text file called `license.mo` placed in the top level directory of the library next to the 'package.mo'-file. It is possible to 
configure a different license file name by changing `MFL_JWT_LICENSE_FILE_FILENAME` in [./CMakePresets.json](./CMakePresets.json) (but you need to keep the `.mo` file extension).

The license file in this example is expected to have one line per username for the users to be licensed, e.g.,
```
model license
/*
name.lastname@company.com
*/
end license;
```

The license manager searches for the first line that starts with `/*` in the file, and expects all lines to contain a username until it encounters a line that starts with `*/`.

## How to build
In the default case you can simply run `./build.sh`. This only builds a release version of the LVE and supporting tools. This is enough for using the example as is.

For debugging reasons use `./build-debug.sh`. This script builds debug configuration as necessary for running the debugger (gdb) and all tests. 
   Building tests requires additional library (https://libcheck.github.io/check/ ) which is 
   automatically installed in dev container. Tests can be run with `./run.sh` which uses `ctest` configured with a 
   CMake Preset in [./CMakePresets.json](./CMakePresets.json)) to run the SEMLA test suite.

## How to Encrypt a Library
The commands below can be run from the `build` directory created when running `build.sh` as described above. The examples assume running on <https://impact.modelon.cloud>. For a local setup you may need to adapt the path.

```
cd build
```

**Tip (optional)**: If you want to test how to encrypt a library on a test library by copy-pasting the commands below into the terminal: Start by creating a test project called `YourLibraryProject`:

```
mkdir -p /home/jovyan/impact/local_projects/YourLibraryProject/YourLibrary && printf "%s\n" "package YourLibrary" "end YourLibrary;" > /home/jovyan/impact/local_projects/YourLibraryProject/YourLibrary/package.mo
```

Locate the Modelon Impact project containing your library. On Modelon Impact cloud installation you can use VSCode in browser launched from the Project explorer app to do that. In this case the opened tab has an ending like `folder=/home/jovyan/impact/local_projects/YourLibraryProject`. Copy the path after folder and add the folder name `YourLibrary`.

Start by encrypting the library using packagetool:
```
./packagetool -version 1.1 -language 3.2 -encrypt "true" -librarypath /home/jovyan/impact/local_projects/YourLibraryProject/YourLibrary/
```
This will encrypt and package the library into `YourLibrary.mol` file. If necessary, you can download this file from the build folder. 

Next step is to add a Modelon Impact specific `project.json` file into the package.

> [!IMPORTANT]  
> The version information in the `project.json` file is used for tracking dependencies
> of workspaces and compiled models. It needs to follow the Semantic Versioning specification
> (<https://semver.org>).
> You MUST always update the project version when releasing the library to users. The project version
> does not need to match Modelica library version.

Copy the `.impact` directory to the build directory:
```
cp -a /home/jovyan/impact/local_projects/YourLibraryProject/.impact .
```
Adapt `build/.impact/project.json` file using a text editor to contain correct version information and skip any unneeded content sections.
You may also consider specifying project icon to be displayed in Workspace Management app, e.g.:
```
{
  "name": "YourLibrary",
  "format": "1.0.0",
  "version": "1.0.0-beta.1",
  "dependencies": [
    {
      "name": "Modelica",
      "versionSpecifier": "4.0.0"
    }
  ],
  "content": [
    {
      "relpath": "YourLibrary",
      "contentType": "MODELICA",
      "name": "YourLibrary",
      "defaultDisabled": false,
      "id": "b984a38211d34c8fab2901a242e963ef"
    }
  ],
  "executionOptions": [],
  "icon": "YourLibrary/Resources/icon.png"
}
```

Add the updated .impact directory into the library package:
```
zip -ur YourLibrary.mol .impact
```

If running on https://impact.modelon.cloud and assuming you have added your
own username to the license file you may test the encryption and licensing by using Modelon Impact Python client, e.g., from a Jupyter notebook:
```
from modelon.impact.client import Client
client = Client()
workspace = client.create_workspace("TestNewLicensing")
new_library_file = "/home/jovyan/impact/local_projects/Semla-license-manager-impact-example/build/YourLibrary.mol"
library = workspace.import_dependency_from_zip(new_library_file).wait()

# compile a test model
model = workspace.get_model("YourLibrary.Example.SomeModel")
dynamic = workspace.get_custom_function('dynamic')
compiler_options = dynamic.get_compiler_options()
fmu = model.compile(compiler_options=compiler_options, compiler_log_level="info").wait()
print(fmu.get_log())

# Cleaning up after testing:
workspace.delete()
library.delete()
```

If the compilation passes without issues your library is ready for distribution on Modelon Impact Cloud.

## How to Update the License File

Assuming provided build and packaging instructions were followed you will have a `build` subdirectory
that contains a number of tools and your encrypted library *YourLibrary.mol* file.
It is possible to update the license file in the library without updating the full package.

To update the license file first extract the library package in a subdirectory:
```
unzip YourLibrary.mol -d YourLibrary/
```
You can now use the *decrypt_file* utility to restore the included license file:
```
./decrypt_file YourLibrary/YourLibrary/ license.moc license.mo
```
This will restore the original *license.mo* file in clear text. Use a text editor
to modify the file to, e.g., add another user name to the list. After the update, use
*encrypt_file* utility to encrypt the file again:
```
./encrypt_file license.mo license.moc YourLibrary/YourLibrary/
```
The newly generated license file will be placed in the library structure. It can be shared
with customers. Alternatively, the file can be updated inside the *mol* file with the zip 
utility. Note that zip utility requires temporary change of working directory:
```
pushd YourLibrary
zip -ur ../YourLibrary.mol YourLibrary/license.moc 
popd
```

## How to Update JWT Keys from wellknown
JWT keys are downloaded as a part of `setup.sh` run and can be updated by running:
```
./update_jwt_keys_from_wellknown.sh
```

The URL to wellknown is set to the Modelon Cloud instance of Impact by default. The URL to wellknown is set in `JWKS_JSON_FILE_URL`  in [./wellknown_url.json](./wellknown_url.json]).

## How to understand

The implementation of the License Manager is specified in <https://help.modelon.com/latest/articles/how_to_third_party_licensing/>.

Good starting points for understanding how the License Manager works is to look at the tests, in particular:
- [./license_manager/tests/test_mfl_license_check.c](./license_manager/tests/test_mfl_license_check.c)
  - tests only the License Manager, without embedding it into an LVE.
- [../SEMLA/src/tests/test_tool.c](../SEMLA/src/tests/test_tool.c) 
  - (the online version of the test is available at [SEMLA: test_tool.c](https://github.com/modelica/Encryption-and-Licensing/blob/master/src/tests/test_tool.c)) tests how a modelica tool uses the LVE (LVE = Library Vendor Executable -- the executable that is responsible for licensing and encryption). The LVE includes the License Manager.
  - This test is disabled when building this License Manager. If you want to run this test, build SEMLA using the CMake build configuration in the SEMLA repo instead (this uses another License Manager), see build instructions in [../SEMLA/src/README.md](../SEMLA/src/README.md) (online version: [SEMLA: src/README.md](https://github.com/modelica/Encryption-and-Licensing/blob/master/src/README.md)).

## How to release

- Run `./release.sh <next_version>` in a terminal standing in this directory (replacing `<next_version>` with a version number of the form `MAJOR.MINOR.PATCH`). This script will:
  - If the files are not already in a git repo, create a new local git repo on the fly.
  - Output a zip file `semla-license-manager-impact-example-<next_version>.zip` containing all files under version control in this repo, plus zip files for the dependencies (which are not under version control)
  - Create a new git tag `v<next_version>` on this repo.
  - If a remote repo  `origin` is configured: push the tag to the remote repo.

