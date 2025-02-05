document.addEventListener('DOMContentLoaded', function () {
    const deleteForms = document.querySelectorAll('.delete-log-form');
    deleteForms.forEach(form => {
        form.addEventListener('submit', function (event) {
            if (!confirm('Are you sure you want to delete this log? This action cannot be undone.')) {
                event.preventDefault();
            }
        });
    });
});