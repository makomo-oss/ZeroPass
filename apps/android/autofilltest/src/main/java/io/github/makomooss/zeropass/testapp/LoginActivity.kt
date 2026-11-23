package io.github.makomooss.zeropass.testapp

import android.app.Activity
import android.os.Bundle
import android.text.InputType
import android.util.Log
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.TextView

/** A plain sign-in form, as many apps have one. */
class LoginActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val column = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            // Below the action bar: the window is edge to edge.
            setPadding(48, 420, 48, 48)
        }
        column.addView(TextView(this).apply { text = "Sign in to the test app" })
        val user = EditText(this).apply {
            id = View.generateViewId()
            hint = "User name"
            inputType = InputType.TYPE_CLASS_TEXT
            setAutofillHints(View.AUTOFILL_HINT_USERNAME)
            tag = "username"
        }
        val password = EditText(this).apply {
            id = View.generateViewId()
            hint = "Password"
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
            setAutofillHints(View.AUTOFILL_HINT_PASSWORD)
        }
        column.addView(user)
        column.addView(password)
        column.addView(Button(this).apply {
            text = "Sign in"
            setOnClickListener {
                Log.i("LoginTest", "signed in as ${user.text} with ${password.text.length} characters")
                finish()
            }
        })
        setContentView(column)
    }
}
