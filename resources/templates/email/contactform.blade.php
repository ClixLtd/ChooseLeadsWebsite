<p>A contact form has been filled in from the website!</p>



<p>
    <table width="600">
        <tr>
            <th align="left" width="100">Name: </th>
            <td align="left">{{ $name }}</td>
        </tr>
        <tr>
            <th align="left">E-Mail: </th>
            <td align="left">{{ $email }}</td>
        </tr>
        <tr>
            <th align="left">Telephone: </th>
            <td align="left">{{ $telephone }}</td>
        </tr>
        <tr><td colspan="2">&nbsp;</td></tr>
        <tr>
            <th align="left" colspan="2">Message: </th>
        </tr>
        <tr>
            <td colspan="2" align="left">{{ $messageContent }}</td>
        </tr>
    </table>
</p>