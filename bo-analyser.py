#Projeto SSof
#Marco Afonso 84610
#Ricardo Ramalho 84623

import sys
import json

#Output Variables
overflown_address = ''
fnname = ''
vuln_function = ''
address = ''
vulnerability = ''
overflow_var = ''
overflown_var = ''

#funcao auxiliar explicar
def openJsonFile(file):
    with open(file) as f:
        data = json.loads(f.read())
    return data

#funcao auxiliar explicar
def outputJsonFile(data):
    data = [data]
    return json.dumps(data)


def addOrDeleteAndAdd(l, valueAddress, destAddress):
    for i in range(len(l)):
        for j in range(len(l[i])):

            if l[i][j] == destAddress:
                del(l[i][j])
                break

    for i in range(len(l)):
        for j in range(len(l[i])):
            if l[i][j] == valueAddress:
                l[i].append(destAddress)

    return l

def returnIndex(l, var):
    for i in range(len(l)):
        for j in range(len(l[i])):
            if l[i][j] == var:
                return i
    return False


def returnParametros(nArgs, op, pos, bytes):
    v = ['rdi', 'rsi', 'rdx']
    v = v[0:nArgs]
    parametersLenght = {}
    counter = 0
    for k in range(pos, -1, -1):
        if counter == nArgs:
            break
        idx = returnIndex(op[k], v[counter])

        if type(idx) == bool:
            continue

        if type(idx) == int:
            parametersLenght[v[counter]] = bytes [idx]
            counter +=1

    return parametersLenght

def varOverflow(data):
    res = {'fnname': '', 'vuln_function': '', 'overflown_var': '', 'vulnerability': '', 'overflow_var': '', 'address': ''}
    #registos
    operations = {}
    allAddresses = []
    allBytes = []
    parameters = {}


    for fun in data:
        variables = data[fun]['variables']
        instructions = data[fun]['instructions']
        for i in range(len(variables)):
            allAddresses.append([variables[i]['address']])
            allBytes.append(variables[i]['bytes'])
            if variables[i]['type'] == 'buffer':
                res['overflow_var'] = variables[i]['name']
            if variables[i]['type'] != 'buffer':
                res['overflown_var'] = variables[i]['name']
                continue

        #print(allAddresses)
        for i in range(len(instructions)):
            if instructions[i]['op'] == 'mov' or instructions[i]['op'] == 'lea':
                valueAddress = instructions[i]['args']['value'].strip("[]")
                destAddress = instructions[i]['args']['dest'].strip("[]")
                allAddresses = addOrDeleteAndAdd(allAddresses, valueAddress, destAddress)
                operations[instructions[i]['pos']] = allAddresses

            if instructions[i]['op'] == 'call':
                if instructions[i]['args']['fnname'] == '<gets@plt>':
                    res['vuln_function'] = fun
                    res['fnname'] = 'gets'
                    res['vulnerability'] = 'VAROVERFLOW'
                    res['address'] = instructions[i]['address']
                if instructions[i]['args']['fnname'] == '<strcpy@plt>':
                    #idx1 = instructions[i]['pos'] - 2
                    #idx2 = instructions[i]['pos'] - 1
                    #lista1 = operations[idx1]
                    #lista2 = operations[idx2]
                    parameters = returnParametros(2, operations, instructions[i]['pos'] - 1, allBytes)
                    if parameters["rsi"] > parameters["rdi"]:
                        res['vuln_function'] = fun
                        res['fnname'] = 'strcpy'
                        res['vulnerability'] = 'VAROVERFLOW'
                        res['address'] = instructions[i]['address']

    print(res)

d = openJsonFile('03_fgets_strcpy_nok_varoverflow.json')
varOverflow(d)
