# **************************************************************************** #
#                                                                              #
#                                                         :::      ::::::::    #
#    Makefile                                           :+:      :+:    :+:    #
#                                                     +:+ +:+         +:+      #
#    By: alvgomez <alvgomez@student.42.fr>          +#+  +:+       +#+         #
#                                                 +#+#+#+#+#+   +#+            #
#    Created: 2022/09/22 15:07:14 by alvgomez          #+#    #+#              #
#    Updated: 2023/05/05 16:52:36 by alvgomez         ###   ########.fr        #
#                                                                              #
# **************************************************************************** #

CC = gcc
FLAGS = -Wall -Wextra -Werror

INC = /sgoinfre/goinfre/Perso/alvgomez/homebrew/opt/openssl@1.1/include
LIB = /sgoinfre/goinfre/Perso/alvgomez/homebrew/opt/openssl@1.1/lib
NAME = corsair.out
SRCS = coRSAir.c
OBJS = ${SRCS:.c=.o}

all:	${NAME}
		 
${NAME}: ${OBJS}
		${CC} ${FLAGS} ${OBJS} -L${LIB} -lssl -lcrypto -o ${NAME}

${OBJS}: ${SRCS}
		${CC} ${FLAGS} -c ${SRCS} -I${INC}

clean:	
		@rm -f ${OBJS}

fclean:	clean
		@rm -f ${NAME}

re: fclean all

.PHONY: all clean fclean re bonus

