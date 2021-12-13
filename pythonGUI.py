import PySimpleGUI as sg


#Class 1
'''layout = [
    [sg.Text('Text Box:'), sg.Input(key='-IN-')],
    [sg.Text('Text Enter Here:',key='-OUT-')],
    [sg.Button('Exit'),sg.Button('Enter')]        
    ]

window = sg.Window('Texto titulo',layout)

while(True):  
    event, values = window.read()
    if event == 'Exit' or event == sg.WIN_CLOSED:
        break
    window['-OUT-'].update(values['-IN-'])

window.close()'''

#Class 2
'''
for i in range(1000):
    sg.one_line_progress_meter('Loader', i + 1, 1000, 'Estableciendo conexión con el servidor...')
'''

#Example to code
'''
sg.theme('GreenTan') 
layout = [[sg.Text('Chat', size=(40, 1))],
          [sg.Output(size=(110, 20), font=('Helvetica 10'))],
          [sg.Multiline(size=(70, 5), enter_submits=False, key='-QUERY-', do_not_clear=False),
           sg.Button('SEND', button_color=(sg.YELLOWS[0], sg.BLUES[0]), bind_return_key=True),
           sg.Button('EXIT', button_color=(sg.YELLOWS[0], sg.GREENS[0]))]]

window = sg.Window('Chat window', layout, font=('Helvetica', ' 13'), default_button_element_size=(8,2), use_default_focus=False)

while True: 
    event, value = window.read()
    if event in (sg.WIN_CLOSED, 'EXIT'):
        break
    if event == 'SEND':
        query = value['-QUERY-'].rstrip()
        print('[Mark]: {}'.format(query), flush=True)

window.close()'''

sg.theme('DarkAmber')

layout_start_menu = [[sg.Text('Write your username:')],
                    [sg.InputText(key='NAME')],
                    [sg.Submit(), sg.Cancel()]]

window_start_menu = sg.Window('SignIn', layout_start_menu)

event, values = window_start_menu.read()
window_start_menu.close()
text = values['NAME']
print(values)

#Ask password
'''
sg.theme('DarkAmber')

layout_password = [[sg.Text('Type the password:')]]

while True:
    event, values = window.read()
'''


sg.theme('DarkAmber')

layout_password = [[sg.Text('Type the password:')],
          [sg.Input(key='-PASSWORD-')],
          [sg.Button('Submit'), sg.Button('Exit')]]

window_password = sg.Window('Request Password', layout_password)

while True:  # Event Loop
    event, values = window_password.read()
    print(event, values)
    if event == sg.WIN_CLOSED or event == 'Exit':
        break
    if event == 'Submit':
        if(values['-PASSWORD-']!= "prueba"):
            sg.popup("Ha entrado una contraseña incorrecta")
window_password.close()