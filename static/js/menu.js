document.addEventListener('DOMContentLoaded', function () {
    const deleteUserForm = document.querySelector('.deleteUser');
    const logoutForm = document.querySelector('.logout');

    if (deleteUserForm) {
        deleteUserForm.addEventListener('submit', function (event) {
            if (!confirm('Are you sure you want to delete your account? This action cannot be undone.')) {
                event.preventDefault();
            }
        });
    }

    if (logoutForm) {
        logoutForm.addEventListener('submit', function (event) {
            if (!confirm('Are you sure you want to logout?')) {
                event.preventDefault();
            }
        });
    }
});