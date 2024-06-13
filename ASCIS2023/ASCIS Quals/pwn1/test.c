#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void setup_buffer();
int calculate(char* expression);
long long evaluate_postfix(long long* postfix);
int is_operator(char token);
int get_precedence(char operator);
int apply_operator(char operator, long long operand1, long long operand2);

int main(int argc, char* argv[]) {
    setup_buffer();
    char buffer[152];
    
    while (1) {
        int input_length = read(0, buffer, 150);
        if (input_length <= 0) {
            break;
        }
        if (input_length <= 3) {
            puts("At least 2 operands and 1 operator");
            exit(1);
        }
        buffer[input_length - 1] = 0;
        calculate(buffer);
    }
    puts("Something wrong");
    exit(1);
}

void setup_buffer() {
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
}

int calculate(char* expression) {
    long long stack[152];
    int stack_top = -1;
    long long postfix[152];
    int postfix_idx = 0;
    
    char* token = strtok(expression, " ");
    while (token != NULL) {
        if (atoi(token) != 0 || *token == '0') {
            postfix[postfix_idx] = atoll(token);
            postfix_idx++;
        }
        else if (is_operator(*token)) {
            while (stack_top >= 0 && is_operator(stack[stack_top]) && get_precedence(*token) <= get_precedence(stack[stack_top])) {
                postfix[postfix_idx] = stack[stack_top];
                stack_top--;
                postfix_idx++;
            }
            stack_top++;
            stack[stack_top] = *token;
        }
        else if (*token == '(') {
            stack_top++;
            stack[stack_top] = *token;
        }
        else if (*token == ')') {
            while (stack_top >= 0 && stack[stack_top] != '(') {
                postfix[postfix_idx] = stack[stack_top];
                stack_top--;
                postfix_idx++;
            }
            if (stack_top >= 0 && stack[stack_top] == '(') {
                stack_top--;
            }
        }
        token = strtok(NULL, " ");
    }
    while (stack_top >= 0) {
        postfix[postfix_idx] = stack[stack_top];
        stack_top--;
        postfix_idx++;
    }
    stack_top = -1;

    stack_top++;
    stack[stack_top] = evaluate_postfix(postfix, postfix_idx);
    printf("%lld\n", stack[stack_top]);
    return stack[stack_top];
}

long long evaluate_postfix(long long* postfix, int postfix_length) {
    long long stack[152];
    int stack_top = -1;
    
    for (int i = 0; i < postfix_length; i++) {
        if (postfix[i] > 0) {
            stack_top++;
            stack[stack_top] = postfix[i];
        }
        else {
            long long operand2 = stack[stack_top];
            stack_top--;
            long long operand1 = stack[stack_top];
            stack_top--;
            long long result = apply_operator(postfix[i], operand1, operand2);
            stack_top++;
            stack[stack_top] = result;
        }
    }
    return stack[stack_top];
}

int is_operator(char token) {
    return token == '+' || token == '-' || token == '*' || token == '/' || token == '^';
}

int get_precedence(char operator) {
    if (operator == '+' || operator == '-') {
        return 1;
    }
    if (operator == '*' || operator == '/') {
        return 2;
    }
    if (operator == '^') {
        return 3;
    }
    return 0;
}

int apply_operator(char operator, long long operand1, long long operand2) {
    switch (operator) {
        case '+':
            return operand1 + operand2;
        case '-':
            return operand1 - operand2;
        case '*':
            return operand1 * operand2;
        case '/':
            return operand1 / operand2;
        case '^':
            return operand1 ^ operand2;
        default:
            return 0;
    }
}

