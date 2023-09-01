package permissionutil

import "os"

// Set permissions for a file using  file.Chmod(os.FileMode(<permission>))
// Example: file.Chmod(os.FileMode(AllReadWriteExecute))
// If you are trying to set permissions using  os.OpenFile then permissions get filtered out by the umask.
// these permissions are 'filtered' by whatever umask has been set.
// https://stackoverflow.com/questions/66097279/why-will-os-openfile-not-create-a-777-file

const (
	os_read        = 04
	os_write       = 02
	os_ex          = 01
	os_user_shift  = 6
	os_group_shift = 3
	os_other_shift = 0

	// User Read Write Execute Permission
	UserRead             = os_read << os_user_shift
	UserWrite            = os_write << os_user_shift
	UserExecute          = os_ex << os_user_shift
	UserReadWrite        = UserRead | UserWrite
	UserReadWriteExecute = UserReadWrite | UserExecute

	// Group Read Write Execute Permission
	GroupRead             = os_read << os_group_shift
	GroupWrite            = os_write << os_group_shift
	GroupExecute          = os_ex << os_group_shift
	GroupReadWrite        = GroupRead | GroupWrite
	GroupReadWriteExecute = GroupReadWrite | GroupExecute

	// Other Read Write Execute Permission
	OtherRead             = os_read << os_other_shift
	OtherWrite            = os_write << os_other_shift
	OtherExecute          = os_ex << os_other_shift
	OtherReadWrite        = OtherRead | OtherWrite
	OtherReadWriteExecute = OtherReadWrite | OtherExecute

	// All Read Write Execute Permission
	AllRead             = UserRead | GroupRead | OtherRead
	AllWrite            = UserWrite | GroupWrite | OtherWrite
	AllExecute          = UserExecute | GroupExecute | OtherExecute
	AllReadWrite        = AllRead | AllWrite
	AllReadWriteExecute = AllReadWrite | AllExecute

	// Default File/Folder Permissions
	ConfigFolderPermission = UserReadWriteExecute
	ConfigFilePermission   = UserReadWrite
	BinaryPermission       = UserRead | UserExecute
	TempFilePermission     = UserReadWrite
)

// UpdateFilePerm modifies the permissions of the given file.
// Returns an error if the file permissions could not be updated.
func UpdateFilePerm(filename string, perm int) error {
	newPerms := os.FileMode(perm)
	return os.Chmod(filename, newPerms)
}
