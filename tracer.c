#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <sys/user.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifndef PTRACE_SYSCALL
#define PTRACE_SYSCALL 24
#endif

#ifndef ORIG_RAX
#ifdef __x86_64__
#define ORIG_RAX 15
#else
#error "Unsupported architecture"
#endif
#endif

#define MAX_STRING_LEN 256

long get_data_at_address(pid_t pid, unsigned long addr)
{
	errno = 0;
	long data = ptrace(PTRACE_PEEKDATA, pid, (void *)addr, NULL);
	if (errno != 0)
	{
		perror("ptrace PEEKDATA");
	}
	return data;
}

char *get_full_data_at_address(pid_t pid, unsigned long addr, size_t max_size)
{
	size_t buffer_size = max_size + 1;
	char *buffer = malloc(buffer_size);
	if (buffer == NULL)
	{
		perror("malloc");
		return NULL;
	}

	size_t i = 0;
	long data;
	while (i < max_size)
	{
		data = get_data_at_address(pid, addr + i);
		if (data == -1)
		{
			free(buffer);
			return NULL;
		}

		memcpy(buffer + i, &data, sizeof(long));
		if (memchr(&data, '\0', sizeof(long)) != NULL)
		{
			break;
		}
		i += sizeof(long);
	}

	buffer[buffer_size - 1] = '\0'; // end of buffer
	return buffer;
}

double measure_time_without_tracer()
{
	struct timespec start, end;
	double time;

	clock_gettime(CLOCK_MONOTONIC, &start);

	pid_t child = fork();
	if (child == 0)
	{
		execl("./target", "tracee_program", NULL);
		perror("execl");
		exit(1);
	}
	else if (child > 0)
	{
		int status;
		waitpid(child, &status, 0);

		clock_gettime(CLOCK_MONOTONIC, &end);

		time = (end.tv_sec - start.tv_sec);
		time += (end.tv_nsec - start.tv_nsec) / 1e9;
		return time;
	}
	else
	{
		perror("fork");
		exit(1);
	}
}

double measure_time_with_tracer()
{
	pid_t child = fork();
	if (child == 0)
	{
		// Child process: Tracee
		printf("Child process started\n");
		if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1)
		{
			perror("ptrace TRACEME");
			exit(1);
		}
		execl("./target", "tracee_program", NULL);
		perror("execl");
		exit(1);
	}
	else if (child > 0)
	{
		// Parent process: Tracer
		int status;
		struct user_regs_struct regs;
		struct timespec start, end;
		double time;

		clock_gettime(CLOCK_MONOTONIC, &start);

		waitpid(child, &status, 0);
		if (WIFEXITED(status))
		{
			printf("Child process exited early\n");
			return 0;
		}

		while (1)
		{
			if (ptrace(PTRACE_SYSCALL, child, NULL, NULL) == -1)
			{
				perror("ptrace SYSCALL");
				exit(1);
			}
			waitpid(child, &status, 0);
			if (WIFEXITED(status))
			{
				printf("Child process exited\n");
				break;
			}
			if (WIFSTOPPED(status))
			{
				int sig = WSTOPSIG(status);
				if (sig == SIGTRAP || sig == (SIGTRAP | 0x80))
				{
					if (ptrace(PTRACE_GETREGS, child, NULL, &regs) == -1)
					{
						perror("ptrace GETREGS");
						exit(1);
					}
					// Check if the system call is WRITE (1)
					if (regs.orig_rax == 1) // write syscall
					{
						printf("System call %llu intercepted (WRITE):\n", regs.orig_rax);
						printf("File descriptor (fd): %llu\n", regs.rdi);
						printf("Memory address of the buffer: %llu\n", regs.rsi);
						printf("Number of bytes to write (count): %llu\n\n", regs.rdx);

						FILE *logfile = fopen("/tmp/statediff", "a");
						if (logfile == NULL)
						{
							perror("fopen");
							exit(1);
						}

						char *data = get_full_data_at_address(child, regs.rsi, regs.rdx);
						if (data != NULL)
						{
							fprintf(logfile, "write(%llu, %s, %llu)\n", regs.rdi, data, regs.rdx);
							free(data);
						}
						else
						{
							fprintf(logfile, "write(%llu, NULL, %llu)\n", regs.rdi, regs.rdx);
						}

						fclose(logfile);
					}
				}
				else
				{
					if (ptrace(PTRACE_CONT, child, NULL, sig) == -1)
					{
						perror("ptrace CONT");
						exit(1);
					}
				}
			}
		}

		clock_gettime(CLOCK_MONOTONIC, &end);

		time = (end.tv_sec - start.tv_sec);
		time += (end.tv_nsec - start.tv_nsec) / 1e9;
		return time;
	}
	else
	{
		perror("fork");
		exit(1);
	}
}

int main()
{
	double time_with_tracer = measure_time_with_tracer();
	double time_without_tracer = measure_time_without_tracer();

	printf("Execution time with tracer: %.6f seconds\n", time_with_tracer);
	printf("Execution time without tracer: %.6f seconds\n", time_without_tracer);

	double overhead = time_with_tracer - time_without_tracer;
	printf("Tracer overhead: %.6f seconds\n", overhead);

	return 0;
}
