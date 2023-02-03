document.querySelector('.img-btn').addEventListener('click', function()
	{
	document.querySelector('.cont').classList.toggle('s-signup')
	}
);

function alert_close() {
	var signin_flash_messages = document.getElementById('signin_flash_messages');
	var signup_flash_messages = document.getElementById('signup_flash_messages');
	signin_flash_messages.style.display = 'none';
	signup_flash_messages.style.display = 'none';
}


function pass(form) {
	var pass1 = document.getElementById('pass1').value;
	var pass2 = document.getElementById('pass2').value;
	var pass_check = document.getElementById('password-check');
	var pass = document.getElementById('alert-{{ category }}');
	if (pass1 == pass2) {
		if (pass1 != "") {
			pass_check.innerHTML = "<b style='color: green;'>Password Matched</b>";
			// document.user_form.method = 'POST';
			document.user_form.action = "/login";
			// alert(form.action);
			// return form;
		}
	}
	else {
		pass_check.innerHTML = "<b style='color: red;'>Password Doesn't Match</b>";
	}
	// function setAction(form) {

		// }
}




