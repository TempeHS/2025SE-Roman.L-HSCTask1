function validateForm() {
    if (!tinymce.get('bodyText')) {
        alert('TinyMCE is not initialized.');
        return false;
    }
    return true;
}
    tinymce.init({
        selector: '#bodyText',
        license_key: 'gpl',
        script_nonce: document.querySelector('script[nonce]').getAttribute('nonce'),
        height: 400,
        plugins: 'advlist autolink lists link charmap preview anchor',
        toolbar: 'undo redo | formatselect | bold italic | bullist numlist | outdent indent',
        menubar: false,
        setup: function(editor) {
            editor.on('change', function () {
                document.getElementById('bodyText').value = editor.getContent();
        });
    },
});