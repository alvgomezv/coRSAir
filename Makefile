# **************************************************************************** #
#                                                                              #
#                                                         :::      ::::::::    #
#    Makefile                                           :+:      :+:    :+:    #
#                                                     +:+ +:+         +:+      #
#    By: alvgomez <alvgomez@student.42.fr>          +#+  +:+       +#+         #
#                                                 +#+#+#+#+#+   +#+            #
#    Created: 2022/09/22 15:07:14 by alvgomez          #+#    #+#              #
#    Updated: 2023/04/27 15:35:52 by alvgomez         ###   ########.fr        #
#                                                                              #
# **************************************************************************** #

CC = gcc
FLAGS = -Wall -Wextra -Werror

INC = /sgoinfre/goinfre/Perso/alvgomez/homebrew/opt/openssl@1.1/include
LIB = /sgoinfre/goinfre/Perso/alvgomez/homebrew/opt/openssl@1.1/lib
NAME = corsair.out
SRCS = coRSAir.c

all:	${NAME}
		 
${NAME}:
		${CC} ${FLAGS} ${SRCS} -I${INC} -L${LIB} -o ${NAME}

clean:	
		@rm -f ${OBJS}

fclean:	clean
		@rm -f ${NAME}

re: fclean all

.PHONY: all clean fclean re bonus