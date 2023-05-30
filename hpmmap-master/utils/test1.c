#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/mman.h>
#include <fcntl.h>

struct test {
  int field1;
  char field2[30];
};

int main() {

  printf("Got to main\n");
/*  
// time count starts
  double total_time;
  clock_t start, end;
  start = clock();

  // some malloc 
  char* str;
  str = (char *) malloc(5000);
  strcpy(str, "HPMMAP TEST");
  str = (char *) realloc(str, 10000);
  strcat(str, "Memory Allocation");
  free(str);

  // more malloc
  struct test *test_ptr;
  test_ptr = (struct test*) malloc (2000 * sizeof(struct test));
*/
  int fd = open("test_txt.bin", O_RDWR, 0666);
  void *test_ptr = mmap(NULL, 4096, PROT_EXEC | PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FILE, fd, 0); 
  if (test_ptr == MAP_FAILED) {
    perror("MMAP failed");
    return -1;
  }
  volatile char buf[4096];
  memcpy(buf, test_ptr, 4096);
  printf("buf[0]: %c", buf[0]);
  printf("MMAP Worked!");
/*
  for(int i = 0; i <2000; ++i) {
     (test_ptr+i)->field1 = i;
     strcpy((test_ptr+i)->field2, "HPMMAP TEST");
  }
  free(test_ptr);

  //time count stops 
  end = clock();
  total_time = ((double) (end - start)) / CLOCKS_PER_SEC;
  //calulate total time
  printf("\nTime taken: %f\n", total_time);
*/
  return 0;

}
